package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReadMFAPreference(ctx context.Context, proof service.Proof) (domain.Preference, error) {
	var result domain.Preference
	err := r.db.QueryRow(ctx, `SELECT COALESCE(p.version,0),COALESCE(p.preferred_method,'')
 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
 LEFT JOIN auth.mfa_preferences p ON p.user_id=u.id
 WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3 AND s.credential_profile='browser'
 AND u.status='active' AND u.deleted_at IS NULL AND s.revoked_at IS NULL
 AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()`, proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&result.Version, &result.Method)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, domain.ErrProofRequired
	}
	return result, err
}

func (r *Repository) UpdateMFAPreference(ctx context.Context, input service.PreferenceUpdate) (domain.Preference, error) {
	var result domain.Preference
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := r.lockPasswordFactorManagement(ctx, tx, input.Proof)
		if err != nil {
			return err
		}
		var before domain.Preference
		err = tx.QueryRow(ctx, `SELECT version,COALESCE(preferred_method,'') FROM auth.mfa_preferences WHERE user_id=$1 FOR UPDATE`, input.UserID).Scan(&before.Version, &before.Method)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if before.Version != input.ExpectedVersion {
			return domain.ErrConflict
		}
		var allowed bool
		if err := tx.QueryRow(ctx, `SELECT $2='' OR $2='totp' AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 OR $2='email' AND auth.email_factor_usable($1) AND NOT auth.has_administrative_access($1)
 OR $2='telegram' AND auth.telegram_factor_usable($1) AND NOT auth.has_administrative_access($1)`, input.UserID, input.Method).Scan(&allowed); err != nil {
			return err
		}
		if !allowed {
			return domain.ErrUnavailable
		}
		if before.Method == input.Method {
			result = before
			return factorManagementDeadline(ctx, tx, deadline)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO auth.mfa_preferences(user_id,preferred_method) VALUES($1,NULLIF($2,''))
 ON CONFLICT(user_id) DO UPDATE SET preferred_method=EXCLUDED.preferred_method,version=auth.mfa_preferences.version+1
 RETURNING version,COALESCE(preferred_method,'')`, input.UserID, input.Method).Scan(&result.Version, &result.Method); err != nil {
			return err
		}
		if err := audit(ctx, tx, input.UserID, "factor_preference_changed"); err != nil {
			return err
		}
		return factorManagementDeadline(ctx, tx, deadline)
	})
	return result, err
}

func clearFactorPreference(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, method domain.Method) error {
	if method == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE auth.mfa_preferences SET preferred_method=NULL,version=version+1 WHERE user_id=$1 AND preferred_method=$2`, user, method)
	return err
}

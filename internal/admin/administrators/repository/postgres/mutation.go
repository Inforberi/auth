package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
)

// AuthorizeMutation joins a caller-owned Read Committed transaction, before project locks.
// Password remains mandatory; enrolled or required MFA also needs a current proof.
func (r *Repository) AuthorizeMutation(ctx context.Context, tx pgx.Tx, actor domain.Principal, permission domain.Permission, freshFor time.Duration) (time.Time, error) {
	if !actor.Valid() || !permission.Valid() {
		return time.Time{}, domain.ErrForbidden
	}
	if tx == nil || freshFor < time.Minute || freshFor > 15*time.Minute {
		return time.Time{}, domain.ErrUnavailable
	}
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	// Shared locks protect revocation without serializing independent project commands.
	for _, lock := range []struct {
		sql  string
		args []any
	}{
		{`SELECT 1 FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL FOR SHARE`, []any{r.realm}},
		{`SELECT 1 FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, []any{actor.UserID}},
		{`SELECT 1 FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2 FOR SHARE`, []any{actor.UserID, permission}},
		{`SELECT 1 WHERE NOT auth.mfa_login_required($1,true)
			OR EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1 FOR SHARE)`, []any{actor.UserID}},
	} {
		var found int
		if err := tx.QueryRow(ctx, lock.sql, lock.args...).Scan(&found); err != nil {
			return time.Time{}, mutationError(ctx, err)
		}
	}
	var deadline time.Time
	err := tx.QueryRow(ctx, `SELECT LEAST(s.expires_at,s.absolute_expires_at,
		s.password_verified_at+$3::double precision*interval '1 second',
		CASE WHEN auth.mfa_login_required(s.user_id,true) THEN s.strong_mfa_verified_at+interval '5 minutes' END)
		FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		JOIN auth.password_credentials p ON p.user_id=s.user_id
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.credential_profile='browser' AND s.primary_method='password'
		AND s.password_verified_at<=clock_timestamp()
		AND (NOT auth.mfa_login_required(s.user_id,true) OR (s.strong_mfa_verified_at<=clock_timestamp()
			AND EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=s.user_id)))
		AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
		FOR SHARE OF s,p`, actor.UserID, actor.TokenHash, freshFor.Seconds()).Scan(&deadline)
	if err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return time.Time{}, mutationError(ctx, err)
	}
	if !fresh {
		return time.Time{}, domain.ErrFreshAuthRequired
	}
	return deadline, nil
}

func mutationError(ctx context.Context, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrForbidden
	}
	return errors.Join(domain.ErrUnavailable, ctx.Err())
}

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ReadEmailFactor(ctx context.Context, proof service.Proof) (*domain.EmailFactor, error) {
	var result domain.EmailFactor
	err := r.db.QueryRow(ctx, `SELECT p.email_factor_allowed,f.user_id IS NOT NULL,
 COALESCE(f.email_id::text,''),f.enabled_at,f.suspended_at,
 auth.email_factor_usable(u.id)
 FROM auth.role_bound_sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
 CROSS JOIN auth.mfa_settings p LEFT JOIN auth.mfa_email f ON f.user_id=u.id
 WHERE p.singleton AND s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
 AND u.status='active' AND u.deleted_at IS NULL AND s.credential_profile='browser'
 AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()`,
		proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&result.Allowed, &result.Configured,
		&result.EmailID, &result.EnabledAt, &result.SuspendedAt, &result.Usable)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrProofRequired
	}
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *Repository) lockEmailFactorManagement(ctx context.Context, tx pgx.Tx, proof service.Proof) (time.Time, error) {
	if r.administrative {
		return time.Time{}, domain.ErrUnavailable
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return time.Time{}, err
	}
	var user string
	if err := tx.QueryRow(ctx, `SELECT id FROM auth.users WHERE id=$1 AND auth_version=$2
 AND status='active' AND deleted_at IS NULL FOR UPDATE`, proof.UserID, proof.AuthVersion).Scan(&user); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, domain.ErrProofRequired
		}
		return time.Time{}, err
	}
	var deadline time.Time
	err := tx.QueryRow(ctx, `SELECT LEAST(s.expires_at,s.absolute_expires_at,s.password_verified_at+interval '5 minutes',
 CASE WHEN auth.mfa_login_required(s.user_id) THEN auth.email_mfa_management_time(s.user_id,s.mfa_method,s.mfa_verified_at)+interval '5 minutes' END)
 FROM auth.role_bound_sessions s JOIN auth.password_credentials p ON p.user_id=s.user_id
 WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3 AND s.credential_profile='browser'
 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
 AND s.primary_method='password' AND s.password_verified_at<=clock_timestamp()
 AND s.password_verified_at>clock_timestamp()-interval '5 minutes'
 AND (NOT auth.mfa_login_required(s.user_id) OR (auth.email_mfa_management_time(s.user_id,s.mfa_method,s.mfa_verified_at)<=clock_timestamp()
  AND auth.email_mfa_management_time(s.user_id,s.mfa_method,s.mfa_verified_at)>clock_timestamp()-interval '5 minutes'))
 AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND (activated_at IS NULL OR password_change_required))
 FOR UPDATE OF s FOR SHARE OF p`, proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, domain.ErrProofRequired
	}
	return deadline, err
}

func emailFactorDeadline(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		return domain.ErrProofRequired
	}
	return nil
}

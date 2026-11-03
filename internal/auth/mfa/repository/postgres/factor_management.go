package postgres

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) lockPasswordFactorManagement(ctx context.Context, tx pgx.Tx, proof mfaservice.Proof) (time.Time, error) {
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

func factorManagementDeadline(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
	var fresh bool
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()<$1`, deadline).Scan(&fresh); err != nil {
		return err
	}
	if !fresh {
		return domain.ErrProofRequired
	}
	return nil
}

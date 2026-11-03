package postgres

import (
	"context"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

// First TOTP enrollment cannot bypass an already enrolled second factor.
func requireConfiguredFactorEnrollmentProof(ctx context.Context, tx pgx.Tx, proof mfaservice.Proof) error {
	var fresh bool
	err := tx.QueryRow(ctx, `SELECT NOT (EXISTS(SELECT 1 FROM auth.mfa_email WHERE user_id=$1)
 OR EXISTS(SELECT 1 FROM auth.mfa_telegram WHERE user_id=$1))
 OR EXISTS(SELECT 1 FROM auth.role_bound_sessions s WHERE s.user_id=$1 AND s.token_hash=$2 AND s.auth_version=$3
 AND auth.email_mfa_management_time(s.user_id,s.mfa_method,s.mfa_verified_at)<=clock_timestamp()
 AND auth.email_mfa_management_time(s.user_id,s.mfa_method,s.mfa_verified_at)>clock_timestamp()-interval '5 minutes')`,
		proof.UserID, proof.TokenHash, proof.AuthVersion).Scan(&fresh)
	if err != nil {
		return err
	}
	if !fresh {
		return domain.ErrProofRequired
	}
	return nil
}

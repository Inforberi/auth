package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type NativeFactorResult struct {
	Proof      service.PrimaryProof
	Target     service.NativeTarget
	VerifiedAt time.Time
	Rejected   bool
}

// The owner holds Access snapshot and commits Rejected attempts, not signing failures.
func CompleteNativeFactor(ctx context.Context, tx pgx.Tx, attempt service.NativeAttempt) (NativeFactorResult, error) {
	var result NativeFactorResult
	proof, err := lockLoginChallengeProfile(ctx, tx, attempt.Digest, attempt.BindingHash, true, "api")
	if err != nil {
		return result, err
	}
	if proof.UserID != attempt.UserID || proof.Administrative || proof.EnrollmentRequired || (proof.Method != "password" && proof.Method != "emailotp") || attempt.Factor == nil {
		return result, domain.ErrInvalidCode
	}
	if attempt.AllowPrimary != nil && !attempt.AllowPrimary(proof.Method, proof.Issuer) {
		return result, domain.ErrInvalidCode
	}
	if err := RequireLoginPrimary(ctx, tx, proof.PrimaryProof); err != nil {
		if errors.Is(err, domain.ErrProofRequired) {
			return result, domain.ErrInvalidCode
		}
		return result, err
	}
	check, recovery := attempt.Factor(proof.UserID)
	verified, err := consumeFactor(ctx, tx, proof.UserID, check, recovery)
	if errors.Is(err, domain.ErrInvalidCode) {
		_, err = tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
		result.Rejected = true
		return result, err
	}
	if err != nil {
		return result, err
	}
	result.Proof, result.Target, result.VerifiedAt = proof.PrimaryProof, proof.Target, verified
	return result, nil
}

func FinishNativeLogin(ctx context.Context, tx pgx.Tx, attempt service.NativeAttempt) error {
	tag, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE digest=$1 AND binding_hash=$2 AND user_id=$3
		AND credential_profile='api' AND expires_at>clock_timestamp() AND attempts<5`, attempt.Digest, attempt.BindingHash, attempt.UserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrInvalidCode
	}
	return audit(ctx, tx, attempt.UserID, "mfa_login_completed")
}

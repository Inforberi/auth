package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func requireLoginEnrollment(ctx context.Context, tx pgx.Tx, input service.LoginEnrollmentParams) (*lockedLoginChallenge, error) {
	proof, err := lockLoginChallenge(ctx, tx, input.ChallengeDigest, input.BindingHash, false)
	if err != nil {
		return nil, err
	}
	if !proof.EnrollmentRequired || proof.Administrative || (input.AllowPrimary != nil && !input.AllowPrimary(proof.Method, proof.Issuer)) {
		return nil, domain.ErrInvalidCode
	}
	if err := requireLoginPrimary(ctx, tx, proof.PrimaryProof); err != nil {
		if errors.Is(err, domain.ErrProofRequired) {
			return nil, domain.ErrInvalidCode
		}
		return nil, err
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT auth.role_requires_mfa($1) AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, proof.UserID).Scan(&allowed); err != nil {
		return nil, err
	}
	if !allowed {
		return nil, domain.ErrInvalidCode
	}
	return proof, nil
}

func (r *Repository) SaveLoginEnrollment(ctx context.Context, input service.LoginEnrollmentParams) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		proof, err := requireLoginEnrollment(ctx, tx, input)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.mfa_enrollments(user_id,digest,auth_version,session_hash,secret,expires_at,purpose)
			VALUES($1,$2,$3,$4,$5,$6,'login') ON CONFLICT(user_id) DO UPDATE
			SET digest=EXCLUDED.digest,auth_version=EXCLUDED.auth_version,session_hash=EXCLUDED.session_hash,
			secret=EXCLUDED.secret,expires_at=EXCLUDED.expires_at,purpose='login',attempts=0,created_at=statement_timestamp()
			RETURNING expires_at`, proof.UserID, input.EnrollmentDigest, proof.AuthVersion, input.ChallengeDigest, input.Secret, proof.ExpiresAt).Scan(&expires)
		if err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "enrollment_started")
	})
	return expires, err
}

func (r *Repository) ConfirmLoginEnrollment(ctx context.Context, input service.LoginEnrollmentParams, check service.Check, recovery []string) error {
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		proof, err := requireLoginEnrollment(ctx, tx, input)
		if err != nil {
			return err
		}
		var secret []byte
		var now time.Time
		err = tx.QueryRow(ctx, `SELECT secret,clock_timestamp() FROM auth.mfa_enrollments
			WHERE user_id=$1 AND digest=$2 AND auth_version=$3 AND session_hash=$4 AND purpose='login'
			AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, proof.UserID, input.EnrollmentDigest, proof.AuthVersion, input.ChallengeDigest).Scan(&secret, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCode
		}
		if err != nil {
			return err
		}
		step, err := check(secret, -1, now)
		if errors.Is(err, domain.ErrInvalidCode) {
			rejected = true
			_, err = tx.Exec(ctx, `UPDATE auth.mfa_enrollments SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
			return err
		}
		if err != nil {
			return err
		}
		return activateEnrollment(ctx, tx, proof.UserID, "login", secret, step, recovery)
	})
	if err != nil {
		return err
	}
	if rejected {
		return domain.ErrInvalidCode
	}
	return nil
}

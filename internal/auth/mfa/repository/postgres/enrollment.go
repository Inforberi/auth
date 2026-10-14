package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) SaveEnrollment(ctx context.Context, proof service.Proof, digest string, encrypted []byte) (time.Time, error) {
	return r.saveEnrollment(ctx, proof, digest, encrypted, "enroll")
}

func (r *Repository) SaveReplacement(ctx context.Context, proof service.Proof, digest string, encrypted []byte) (time.Time, error) {
	return r.saveEnrollment(ctx, proof, digest, encrypted, "replace")
}

func (r *Repository) saveEnrollment(ctx context.Context, proof service.Proof, digest string, encrypted []byte, purpose string) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := r.requireProof(ctx, tx, proof); err != nil {
			return err
		}
		if purpose == "replace" {
			if err := requireFreshMFA(ctx, tx, proof); err != nil {
				return err
			}
		}
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)`, proof.UserID).Scan(&enabled); err != nil {
			return err
		}
		if enabled != (purpose == "replace") {
			return domain.ErrConflict
		}
		err := tx.QueryRow(ctx, `INSERT INTO auth.mfa_enrollments(user_id,digest,auth_version,session_hash,secret,expires_at,purpose)
			VALUES ($1,$2,$3,$4,$5,statement_timestamp()+interval '10 minutes',$6)
			ON CONFLICT(user_id) DO UPDATE SET digest=EXCLUDED.digest,auth_version=EXCLUDED.auth_version,
			session_hash=EXCLUDED.session_hash,secret=EXCLUDED.secret,purpose=EXCLUDED.purpose,attempts=0,created_at=statement_timestamp(),expires_at=EXCLUDED.expires_at
			RETURNING expires_at`, proof.UserID, digest, proof.AuthVersion, proof.TokenHash, encrypted, purpose).Scan(&expires)
		if err != nil {
			return err
		}
		return audit(ctx, tx, proof.UserID, "enrollment_started")
	})
	return expires, err
}

func (r *Repository) ConfirmEnrollment(ctx context.Context, proof service.Proof, digest string, check service.Check, recovery []string) error {
	return r.confirmEnrollment(ctx, proof, digest, check, recovery, "enroll")
}

func (r *Repository) ConfirmReplacement(ctx context.Context, proof service.Proof, digest string, check service.Check, recovery []string) error {
	return r.confirmEnrollment(ctx, proof, digest, check, recovery, "replace")
}

func (r *Repository) confirmEnrollment(ctx context.Context, proof service.Proof, digest string, check service.Check, recovery []string, purpose string) error {
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := r.requireProof(ctx, tx, proof); err != nil {
			return err
		}
		if purpose == "replace" {
			if err := requireFreshMFA(ctx, tx, proof); err != nil {
				return err
			}
		}
		var secret []byte
		var now time.Time
		err := tx.QueryRow(ctx, `SELECT secret,clock_timestamp() FROM auth.mfa_enrollments
			WHERE user_id=$1 AND digest=$2 AND auth_version=$3 AND session_hash=$4
			AND expires_at>clock_timestamp() AND attempts<5 AND purpose=$5 FOR UPDATE`, proof.UserID, digest, proof.AuthVersion, proof.TokenHash, purpose).Scan(&secret, &now)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidCode
		}
		if err != nil {
			return err
		}
		step, err := check(secret, -1, now)
		if errors.Is(err, domain.ErrInvalidCode) {
			rejected = true
			_, err := tx.Exec(ctx, `UPDATE auth.mfa_enrollments SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
			return err
		}
		if err != nil {
			return err
		}
		if purpose == "replace" {
			if _, err := tx.Exec(ctx, `UPDATE auth.mfa_totp SET secret=$2,last_step=$3,enabled_at=clock_timestamp() WHERE user_id=$1`, proof.UserID, secret, step); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1`, proof.UserID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES ($1,$2,$3)`, proof.UserID, secret, step); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) SELECT $1,unnest($2::text[])`, proof.UserID, recovery); err != nil {
			return err
		}
		if err := invalidateFactors(ctx, tx, proof.UserID); err != nil {
			return err
		}
		event := "totp_enabled"
		if purpose == "replace" {
			event = "totp_replaced"
		}
		return audit(ctx, tx, proof.UserID, event)
	})
	if err != nil {
		return err
	}
	if rejected {
		return domain.ErrInvalidCode
	}
	return nil
}

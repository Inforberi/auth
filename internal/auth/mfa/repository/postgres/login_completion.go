package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) CompleteLogin(ctx context.Context, input service.LoginCompletion, factor service.LoginFactor) (*service.LoginCommit, error) {
	var result service.LoginCommit
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		proof, err := lockLoginChallenge(ctx, tx, input.Digest, input.BindingHash, false)
		if err != nil {
			return err
		}
		if proof.EnrollmentRequired {
			return domain.ErrInvalidCode
		}
		if !proof.Administrative && input.AllowPrimary != nil && !input.AllowPrimary(proof.Method, proof.Issuer) {
			return domain.ErrInvalidCode
		}
		if err := requireLoginPrimary(ctx, tx, proof.PrimaryProof); err != nil {
			if errors.Is(err, domain.ErrProofRequired) {
				return domain.ErrInvalidCode
			}
			return err
		}
		check, recovery := factor(proof.UserID)
		verified, err := consumeFactor(ctx, tx, proof.UserID, check, recovery)
		if errors.Is(err, domain.ErrInvalidCode) {
			rejected = true
			_, err := tx.Exec(ctx, `UPDATE auth.mfa_login_challenges SET attempts=attempts+1 WHERE user_id=$1`, proof.UserID)
			return err
		}
		if err != nil {
			return err
		}
		// SQL owns the authentication times and session lifetime; no caller-provided MFA timestamp.
		err = tx.QueryRow(ctx, `INSERT INTO auth.sessions
			(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,user_agent,ip_address,
			primary_method,primary_verified_at,mfa_verified_at,password_verified_at,idle_timeout_seconds,activity_interval_seconds,admin_absolute_seconds)
			VALUES ($1,$2,$3,statement_timestamp(),statement_timestamp()+$4::double precision*interval '1 second',
			statement_timestamp()+$5::double precision*interval '1 second',$6,$7,$8,$9,$10,
			CASE WHEN $11::boolean THEN $9::timestamptz ELSE NULL END,
			COALESCE(NULLIF($12,0),1800),COALESCE(NULLIF($13,0),60),COALESCE(NULLIF($14,0),43200)) RETURNING expires_at`,
			input.SessionHash, proof.UserID, proof.AuthVersion, input.SessionTTL.Seconds(), input.AbsoluteSessionTTL.Seconds(),
			input.UserAgent, input.IP, proof.Method, proof.VerifiedAt, verified, proof.Administrative,
			int64(input.AdminIdleTimeout/time.Second), int64(input.AdminActivityInterval/time.Second), int64(input.AdminAbsoluteTTL/time.Second)).Scan(&result.ExpiresAt)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "mfa_login_completed"); err != nil {
			return err
		}
		result.UserID, result.MFAVerified = proof.UserID, verified
		return nil
	})
	if err != nil {
		return nil, err
	}
	if rejected {
		return nil, domain.ErrInvalidCode
	}
	return &result, nil
}

type lockedLoginChallenge struct {
	service.PrimaryProof
	EnrollmentRequired bool
	ExpiresAt          time.Time
}

func lockLoginChallenge(ctx context.Context, tx pgx.Tx, digest, binding string, accessLocked bool) (*lockedLoginChallenge, error) {
	var user accountdomain.UserID
	var administrative bool
	// Inspect intent without locking; administrative flows take Access before user/challenge/factor locks.
	err := tx.QueryRow(ctx, `SELECT user_id,administrative FROM auth.mfa_login_challenges
		WHERE digest=$1 AND binding_hash=$2`, digest, binding).Scan(&user, &administrative)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	if administrative && !accessLocked {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return nil, err
		}
	}
	var version int64
	err = tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1
		AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	if err != nil {
		return nil, err
	}
	proof := lockedLoginChallenge{PrimaryProof: service.PrimaryProof{UserID: user, AuthVersion: version, Administrative: administrative}}
	err = tx.QueryRow(ctx, `SELECT primary_method,primary_reference,primary_issuer,primary_verified_at,enrollment_required,expires_at
		FROM auth.mfa_login_challenges WHERE user_id=$1 AND digest=$2 AND binding_hash=$3 AND auth_version=$4
		AND administrative=$5 AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, user, digest, binding, version, administrative).
		Scan(&proof.Method, &proof.Reference, &proof.Issuer, &proof.VerifiedAt, &proof.EnrollmentRequired, &proof.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	return &proof, err
}

package postgres

import (
	"context"
	"errors"
	"time"

	pgx "github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
)

func (r *Repository) CompleteLogin(ctx context.Context, input mfalogin.LoginCompletion, factor mfalogin.LoginFactor) (*mfalogin.LoginCommit, error) {
	var result mfalogin.LoginCommit
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
		if err := RequireLoginPrimary(ctx, tx, proof.PrimaryProof); err != nil {
			if errors.Is(err, domain.ErrProofRequired) {
				return domain.ErrInvalidCode
			}
			return err
		}
		verified, err := consumeLoginFactor(ctx, tx, *proof, factor, input.Email, input.Telegram)
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
			primary_method,primary_verified_at,mfa_verified_at,password_verified_at,idle_timeout_seconds,activity_interval_seconds,admin_absolute_seconds,mfa_method)
			VALUES ($1,$2,$3,statement_timestamp(),statement_timestamp()+$4::double precision*interval '1 second',
			statement_timestamp()+$5::double precision*interval '1 second',$6,$7,$8,$9,$10,
			CASE WHEN $11::boolean THEN $9::timestamptz ELSE NULL END,
			COALESCE(NULLIF($12,0),1800),COALESCE(NULLIF($13,0),60),COALESCE(NULLIF($14,0),43200),$15) RETURNING expires_at`,
			input.SessionHash, proof.UserID, proof.AuthVersion, input.SessionTTL.Seconds(), input.AbsoluteSessionTTL.Seconds(),
			input.UserAgent, input.IP, proof.Method, proof.VerifiedAt, verified.VerifiedAt, proof.Administrative,
			int64(input.AdminIdleTimeout/time.Second), int64(input.AdminActivityInterval/time.Second), int64(input.AdminAbsoluteTTL/time.Second), verified.Method).Scan(&result.ExpiresAt)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if err := audit(ctx, tx, proof.UserID, "mfa_login_completed"); err != nil {
			return err
		}
		result.UserID, result.MFAVerified = proof.UserID, verified.VerifiedAt
		return requireLoginDeadline(ctx, tx, proof.ExpiresAt)
	})
	if err != nil {
		return nil, err
	}
	if rejected {
		return nil, domain.ErrInvalidCode
	}
	return &result, nil
}

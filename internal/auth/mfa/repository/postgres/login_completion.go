package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) CompleteLogin(ctx context.Context, input service.LoginCompletion, factor service.LoginFactor) (*service.LoginCommit, error) {
	var result service.LoginCommit
	rejected := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		proof, err := lockLoginChallenge(ctx, tx, input.Digest, input.BindingHash)
		if err != nil {
			return err
		}
		if input.AllowPrimary != nil && !input.AllowPrimary(proof.Method, proof.Issuer) {
			return domain.ErrInvalidCode
		}
		if err := requireLoginPrimary(ctx, tx, *proof); err != nil {
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
			primary_method,primary_verified_at,mfa_verified_at)
			VALUES ($1,$2,$3,statement_timestamp(),statement_timestamp()+$4::double precision*interval '1 second',
			statement_timestamp()+$5::double precision*interval '1 second',$6,$7,$8,$9,$10) RETURNING expires_at`,
			input.SessionHash, proof.UserID, proof.AuthVersion, input.SessionTTL.Seconds(), input.AbsoluteSessionTTL.Seconds(),
			input.UserAgent, input.IP, proof.Method, proof.VerifiedAt, verified).Scan(&result.ExpiresAt)
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

func lockLoginChallenge(ctx context.Context, tx pgx.Tx, digest, binding string) (*service.PrimaryProof, error) {
	var user accountdomain.UserID
	// Lookup is non-locking: all mutations lock user -> challenge -> factor -> session.
	err := tx.QueryRow(ctx, `SELECT user_id FROM auth.mfa_login_challenges
		WHERE digest=$1 AND binding_hash=$2`, digest, binding).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	if err != nil {
		return nil, err
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
	proof := service.PrimaryProof{UserID: user, AuthVersion: version}
	err = tx.QueryRow(ctx, `SELECT primary_method,primary_reference,primary_issuer,primary_verified_at
		FROM auth.mfa_login_challenges WHERE user_id=$1 AND digest=$2 AND binding_hash=$3 AND auth_version=$4
		AND expires_at>clock_timestamp() AND attempts<5 FOR UPDATE`, user, digest, binding, version).
		Scan(&proof.Method, &proof.Reference, &proof.Issuer, &proof.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrInvalidCode
	}
	return &proof, err
}

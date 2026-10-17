package postgres

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) ConfirmReauthentication(ctx context.Context, proof mfaservice.Proof, digest, verifier, replacement string) (*service.ReauthenticatedSession, error) {
	var result service.ReauthenticatedSession
	accepted := false
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockReauthenticationSession(ctx, tx, proof); err != nil {
			return err
		}
		var expected, emailID string
		err := tx.QueryRow(ctx, `SELECT c.verifier,c.email_id FROM auth.email_login_challenges c
			JOIN auth.user_emails e ON e.id=c.email_id AND e.user_id=c.user_id
			WHERE c.digest=$1 AND c.user_id=$2 AND c.auth_version=$3 AND c.session_hash=$4
			AND c.purpose='reauthenticate' AND c.credential_profile='browser' AND c.attempts<5 AND c.expires_at>clock_timestamp()
			AND e.verified_at IS NOT NULL FOR UPDATE OF c`, digest, proof.UserID, proof.AuthVersion, proof.TokenHash).
			Scan(&expected, &emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(verifier)) != 1 {
			return recordFailedCode(ctx, tx, digest)
		}
		err = tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions SET token_hash=$3,email_reauthenticated_id=$4,
			email_reauthenticated_at=clock_timestamp() WHERE user_id=$1 AND token_hash=$2
			AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
			RETURNING email_reauthenticated_at,LEAST(expires_at,absolute_expires_at)`,
			proof.UserID, proof.TokenHash, replacement, emailID).Scan(&result.VerifiedAt, &result.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return mfadomain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE digest=$1`, digest); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_audit(user_id,event,auth_version)
			VALUES ($1,'email_reauthenticated',$2)`, proof.UserID, proof.AuthVersion); err != nil {
			return err
		}
		accepted = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, domain.ErrInvalidCode
	}
	return &result, nil
}

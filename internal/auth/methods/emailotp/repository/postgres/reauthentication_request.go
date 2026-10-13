package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func lockReauthenticationSession(ctx context.Context, tx pgx.Tx, proof mfaservice.Proof) error {
	var version int64
	err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1
		AND status='active' AND deleted_at IS NULL FOR UPDATE`, proof.UserID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && version != proof.AuthVersion {
		return mfadomain.ErrProofRequired
	}
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT id FROM auth.sessions s WHERE s.user_id=$1 AND s.token_hash=$2
		AND s.auth_version=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
		AND s.absolute_expires_at>clock_timestamp()
		AND NOT EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL)
		AND EXISTS(SELECT 1 FROM auth.linked_identities WHERE user_id=$1) FOR UPDATE OF s`,
		proof.UserID, proof.TokenHash, version).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return mfadomain.ErrProofRequired
	}
	return err
}

func (r *Repository) IssueReauthentication(ctx context.Context, proof mfaservice.Proof, email string, c domain.Challenge) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		if err := lockReauthenticationSession(ctx, tx, proof); err != nil {
			return err
		}
		var emailID string
		err := tx.QueryRow(ctx, `SELECT id FROM auth.user_emails WHERE user_id=$1 AND email=$2
			AND verified_at IS NOT NULL`, proof.UserID, email).Scan(&emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return mfadomain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE user_id=$1`, proof.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_challenges
			(digest,user_id,email_id,auth_version,verifier,expires_at,purpose,session_hash)
			VALUES ($1,$2,$3,$4,$5,$6,'reauthenticate',$7)`, c.Digest, proof.UserID, emailID,
			proof.AuthVersion, c.Verifier, c.ExpiresAt, proof.TokenHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_outbox(digest,payload,expires_at) VALUES ($1,$2,$3)`, c.Digest, c.Payload, c.ExpiresAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.email_login_audit(user_id,event,auth_version)
			VALUES ($1,'reauthentication_issued',$2)`, proof.UserID, proof.AuthVersion)
		return err
	})
}

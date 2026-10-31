package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (r *Repository) IssueEmailPreparation(ctx context.Context, proof mfaservice.Proof, email string, c domain.Challenge) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		deadline, err := lockEmailPreparationSession(ctx, tx, proof)
		if err != nil {
			return err
		}
		var emailID string
		err = tx.QueryRow(ctx, `SELECT id FROM auth.user_emails WHERE user_id=$1 AND email=$2 AND verified_at IS NOT NULL FOR SHARE`, proof.UserID, email).Scan(&emailID)
		if errors.Is(err, pgx.ErrNoRows) {
			return mfadomain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_login_challenges WHERE user_id=$1 AND purpose='mfa_email_prepare'`, proof.UserID); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO auth.email_login_challenges(digest,user_id,email_id,auth_version,verifier,expires_at,purpose,session_hash)
 SELECT $1,$2,$3,$4,$5,LEAST($6::timestamptz,$8::timestamptz),'mfa_email_prepare',$7
 WHERE clock_timestamp()<LEAST($6::timestamptz,$8::timestamptz) RETURNING expires_at`, c.Digest, proof.UserID, emailID, proof.AuthVersion, c.Verifier, c.ExpiresAt, proof.TokenHash, deadline).Scan(&expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return mfadomain.ErrProofRequired
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.email_login_outbox(digest,payload,expires_at) VALUES($1,$2,$3)`, c.Digest, c.Payload, expires); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.email_login_audit(user_id,event,auth_version) VALUES($1,'email_factor_preparation_issued',$2)`, proof.UserID, proof.AuthVersion)
		if err != nil {
			return err
		}
		return checkEmailPreparationDeadline(ctx, tx, deadline)
	})
	return expires, err
}

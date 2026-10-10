package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) Issue(ctx context.Context, email string, prepared domain.Verification, cooldown time.Duration) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var id domain.AddressID
		var user domain.UserID
		var eligible bool
		err := tx.QueryRow(ctx, `SELECT e.id, e.user_id
			FROM auth.user_emails e JOIN auth.users u ON u.id=e.user_id
			WHERE e.email=$1 AND u.status='active' AND u.deleted_at IS NULL FOR UPDATE OF u`, email).Scan(&id, &user)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// Lock the account before its contact, then read eligibility after any competing commit.
		if err := tx.QueryRow(ctx, `SELECT verified_at IS NULL AND
			(verification_sent_at IS NULL OR verification_sent_at <= now() - $2::double precision * interval '1 second')
			FROM auth.user_emails WHERE id=$1 FOR UPDATE`, id, cooldown.Seconds()).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return nil
		}
		return r.QueueInTransaction(ctx, tx, user, id, prepared)
	})
}

func (r *Repository) QueueInTransaction(ctx context.Context, tx pgx.Tx, user domain.UserID, email domain.AddressID, prepared domain.Verification) error {
	// Caller owns the account/contact locks and commits this intent with registration or resend.
	if _, err := tx.Exec(ctx, `DELETE FROM auth.email_verifications WHERE email_id=$1`, email); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.email_verifications(digest,email_id,expires_at) VALUES ($1,$2,$3)`, prepared.Digest, email, prepared.ExpiresAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.email_verification_outbox(digest,payload,expires_at) VALUES ($1,$2,$3)`, prepared.Digest, prepared.Payload, prepared.ExpiresAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.user_emails SET verification_sent_at=now() WHERE id=$1`, email); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.email_verification_audit(user_id,event) VALUES ($1,'email_verification_issued')`, user)
	return err
}

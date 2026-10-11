package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ConfirmEmailChange(ctx context.Context, digest string) error {
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var user domain.UserID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM auth.email_changes WHERE confirm_digest=$1`, digest).Scan(&user); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrInvalidEmailChange
			}
			return err
		}
		version, err := lockChangeAccount(ctx, tx, user)
		if err != nil {
			return err
		}
		var id, session, newEmail string
		var oldID domain.AddressID
		var expected domain.AuthVersion
		var payload []byte
		var protection time.Time
		err = tx.QueryRow(ctx, `SELECT c.id,c.email_id,c.new_email,c.session_hash,c.auth_version,c.completion_payload,c.protect_until
			FROM auth.email_changes c JOIN auth.password_credentials p ON p.user_id=c.user_id AND p.email_id=c.email_id
			JOIN auth.user_emails e ON e.id=c.email_id AND e.email=c.old_email AND e.verified_at IS NOT NULL
			WHERE c.confirm_digest=$1 AND c.state='pending' AND c.expires_at>clock_timestamp() FOR UPDATE OF c`, digest).
			Scan(&id, &oldID, &newEmail, &session, &expected, &payload, &protection)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidEmailChange
		}
		if err != nil {
			return err
		}
		if version != expected {
			return domain.ErrInvalidEmailChange
		}
		if err := requireChangeSession(ctx, tx, user, session, version, 0); err != nil {
			return err
		}
		var newID domain.AddressID
		if err := tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES ($1,$2,clock_timestamp()) RETURNING id`, user, newEmail).Scan(&newID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET email_id=$2 WHERE user_id=$1`, user, newID); err != nil {
			return err
		}
		// Mark completed before clearing pending changes; keep the old-address protection alive.
		if _, err := tx.Exec(ctx, `UPDATE auth.email_changes SET state='completed' WHERE id=$1`, id); err != nil {
			return err
		}
		if err := invalidateChangeAccess(ctx, tx, user); err != nil {
			return err
		}
		if err := queueChangeMail(ctx, tx, id, "completed", payload, protection); err != nil {
			return err
		}
		return auditEmailChange(ctx, tx, user, id, "confirmed")
	})
	return emailOwnershipError(err)
}

package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ReportEmailChange(ctx context.Context, digest string) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		var user domain.UserID
		if err := tx.QueryRow(ctx, `SELECT user_id FROM auth.email_changes WHERE report_digest=$1`, digest).Scan(&user); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrInvalidEmailChange
			}
			return err
		}
		if _, err := lockChangeAccount(ctx, tx, user); err != nil {
			return err
		}
		var id, state string
		err := tx.QueryRow(ctx, `SELECT id,state FROM auth.email_changes WHERE report_digest=$1
			AND state IN ('pending','completed') AND protect_until>clock_timestamp() FOR UPDATE`, digest).Scan(&id, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidEmailChange
		}
		if err != nil {
			return err
		}
		event := "cancelled"
		if state == "completed" {
			event = "reported"
			if _, err := tx.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, user); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.email_changes SET state=$2 WHERE id=$1`, id, event); err != nil {
			return err
		}
		if err := invalidateChangeAccess(ctx, tx, user); err != nil {
			return err
		}
		// Consume other completed protection tokens as well; a later recovery must not leave old blocking links.
		if event == "reported" {
			if _, err := tx.Exec(ctx, `UPDATE auth.email_changes SET state='reported' WHERE user_id=$1 AND state='completed'`, user); err != nil {
				return err
			}
		}
		return auditEmailChange(ctx, tx, user, id, event)
	})
}

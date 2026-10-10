package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) IssueReset(ctx context.Context, email string, prepared domain.ResetChallenge) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var user accountdomain.UserID
		var version int64
		err := tx.QueryRow(ctx, `
			SELECT u.id, u.auth_version
			FROM auth.users u
			JOIN auth.password_credentials p ON p.user_id = u.id
			JOIN auth.user_emails e ON e.id = p.email_id AND e.user_id = u.id
			WHERE e.email = $1 AND u.status = 'active' AND u.deleted_at IS NULL
			FOR UPDATE OF u`, email).Scan(&user, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var cooldown bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_resets WHERE user_id=$1 AND created_at>clock_timestamp()-interval '1 minute')`, user).Scan(&cooldown); err != nil {
			return err
		}
		if cooldown {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.password_resets WHERE user_id=$1`, user); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_resets(digest,user_id,auth_version,expires_at) VALUES ($1,$2,$3,$4)`, prepared.Digest, user, version, prepared.ExpiresAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.password_reset_outbox(digest,payload,expires_at) VALUES ($1,$2,$3)`, prepared.Digest, prepared.Payload, prepared.ExpiresAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,'password_reset_issued')`, user)
		return err
	})
}

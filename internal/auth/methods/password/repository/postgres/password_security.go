package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func revokeForPassword(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, event string) error {
	if err := invalidatePasswordSessions(ctx, tx, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES($1,$2)`, user, event)
	return err
}

func invalidatePasswordSessions(ctx context.Context, tx pgx.Tx, user accountdomain.UserID) error {
	for _, query := range []string{
		`UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`,
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
		`DELETE FROM auth.password_resets WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, user); err != nil {
			return err
		}
	}
	return nil
}

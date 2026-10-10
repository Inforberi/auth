package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) ChangePassword(ctx context.Context, user accountdomain.UserID, session, expectedHash, newHash string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR UPDATE`, user).Scan(&version); err != nil {
			return err
		}
		var valid bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE token_hash=$1 AND user_id=$2 AND auth_version=$3
			AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp())`, session, user, version).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return domain.ErrInvalidEmailOrPassword
		}
		result, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET password_hash=$3 WHERE user_id=$1 AND password_hash=$2`, user, expectedHash, newHash)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrInvalidEmailOrPassword
		}
		return revokeForPassword(ctx, tx, user, "password_changed")
	})
}

func revokeForPassword(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, event string) error {
	if _, err := tx.Exec(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, user); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, user); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.password_resets WHERE user_id=$1`, user); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,$2)`, user, event)
	return err
}

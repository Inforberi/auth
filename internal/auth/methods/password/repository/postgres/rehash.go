package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) RehashPassword(ctx context.Context, user accountdomain.UserID, expectedVersion int64, expectedHash, newHash string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users
   WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, user).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			return passworddomain.ErrInvalidEmailOrPassword
		}
		if err != nil {
			return err
		}
		if version != expectedVersion {
			return passworddomain.ErrInvalidEmailOrPassword
		}
		// CAS сохраняет результат параллельного rehash; смена пароля блокируется версией выше.
		_, err = tx.Exec(ctx, `UPDATE auth.password_credentials SET password_hash=$3
   WHERE user_id=$1 AND password_hash=$2`, user, expectedHash, newHash)
		return err
	})
}

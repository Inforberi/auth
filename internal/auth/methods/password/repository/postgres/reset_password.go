package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (r *PasswordRepo) ConsumeReset(ctx context.Context, digest, passwordHash string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var user accountdomain.UserID
		var version int64
		err := tx.QueryRow(ctx, `
			SELECT u.id, u.auth_version
			FROM auth.users u
			JOIN auth.password_resets r ON r.user_id = u.id
			WHERE r.digest = $1
			FOR UPDATE OF u`, digest).Scan(&user, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrInvalidReset
		}
		if err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `
			DELETE FROM auth.password_resets r
			USING auth.users u
			WHERE r.digest = $1 AND r.user_id = u.id
			AND r.auth_version = $2 AND u.auth_version = $2
			AND u.status = 'active' AND u.deleted_at IS NULL
			AND r.expires_at > clock_timestamp()`, digest, version)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return domain.ErrInvalidReset
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1`, user, passwordHash); err != nil {
			return err
		}
		return revokeForPassword(ctx, tx, user, "password_reset")
	})
}

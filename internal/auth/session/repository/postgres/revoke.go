package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) DeleteSession(ctx context.Context, token string, user accountdomain.UserID) error {
	_, err := r.db.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND user_id=$2 AND revoked_at IS NULL`, token, user)
	return err
}

func (r *Repository) DeleteAllSessions(ctx context.Context, user accountdomain.UserID) error {
	return r.DeleteAllSessionsExcept(ctx, user, "")
}

func (r *Repository) DeleteAllSessionsExcept(ctx context.Context, user accountdomain.UserID, keep string) error {
	return r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, user).Scan(&version); err != nil {
			return sessionError(err)
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND token_hash<>$2 AND revoked_at IS NULL`, user, keep); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE auth.sessions SET auth_version=$3 WHERE user_id=$1 AND token_hash=$2 AND auth_version=$3-1 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()`, user, keep, version)
		if err != nil {
			return err
		}
		if keep != "" && result.RowsAffected() != 1 {
			return sessionError(pgx.ErrNoRows)
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event) VALUES ($1,'sessions_revoked')`, user)
		return err
	})
}

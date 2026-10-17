package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) RotateSession(ctx context.Context, user accountdomain.UserID, currentHash, replacementHash string) (time.Time, error) {
	var expires time.Time
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users
			WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, user).Scan(&version); err != nil {
			return sessionError(err)
		}
		// The old verifier is consumed by the UPDATE; concurrent rotations have one winner.
		err := tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions SET token_hash=$3
			WHERE user_id=$1 AND token_hash=$2 AND auth_version=$4 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
			RETURNING LEAST(expires_at,absolute_expires_at)`, user, currentHash, replacementHash, version).Scan(&expires)
		return sessionError(err)
	})
	return expires, err
}

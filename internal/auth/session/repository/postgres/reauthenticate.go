package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

func (r *Repository) ConfirmPassword(ctx context.Context, user accountdomain.UserID, currentHash, expectedPassword string, expectedVersion int64, replacementHash string) (*domain.PasswordConfirmation, error) {
	var proof domain.PasswordConfirmation
	err := r.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT auth_version FROM auth.users
			WHERE id=$1 AND status='active' AND deleted_at IS NULL FOR SHARE`, user).Scan(&version); err != nil {
			return sessionError(err)
		}
		if version != expectedVersion {
			return domain.ErrSessionNotFound
		}
		// Password checking happens before this transaction; bind its result to current credentials.
		err := tx.QueryRow(ctx, `UPDATE auth.role_bound_sessions SET token_hash=$3,password_verified_at=clock_timestamp()
			WHERE user_id=$1 AND token_hash=$2 AND auth_version=$4 AND revoked_at IS NULL
			AND expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp()
			AND EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=$1 AND password_hash=$5)
			RETURNING password_verified_at,LEAST(expires_at,absolute_expires_at)`, user, currentHash, replacementHash, version, expectedPassword).
			Scan(&proof.VerifiedAt, &proof.ExpiresAt)
		if err != nil {
			return sessionError(err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,actor_id,event,auth_version)
			VALUES ($1,$1,'password_reauthenticated',$2)`, user, version)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &proof, nil
}

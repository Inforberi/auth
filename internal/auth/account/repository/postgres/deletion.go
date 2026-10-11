package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) DeleteAccount(ctx context.Context, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var deleted *time.Time
		err := tx.QueryRow(ctx, `SELECT auth_version,deleted_at FROM auth.users WHERE id=$1 FOR UPDATE`, deletion.UserID).Scan(&version, &deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAccountNotFound
		}
		if err != nil {
			return err
		}
		if version != deletion.ExpectedVersion {
			return domain.ErrAccountConflict
		}
		// Retry with the current version is a no-op, never a restoration.
		if deleted != nil {
			return nil
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.users SET email_reuse_blocked=(status='blocked'),status='blocked',deleted_at=clock_timestamp(),
			auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, deletion.UserID).Scan(&version); err != nil {
			return err
		}
		for _, query := range []string{
			`UPDATE auth.sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()),user_agent='',ip_address='' WHERE user_id=$1`,
			`DELETE FROM auth.password_credentials WHERE user_id=$1`,
			`DELETE FROM auth.temporary_password_credentials WHERE user_id=$1`,
			`DELETE FROM auth.account_invitations WHERE user_id=$1`,
			`DELETE FROM auth.email_verifications v USING auth.user_emails e WHERE v.email_id=e.id AND e.user_id=$1`,
			`DELETE FROM auth.email_changes WHERE user_id=$1`,
			`DELETE FROM auth.user_profile WHERE user_id=$1`,
			`UPDATE auth.user_emails SET verified_at=NULL,verification_sent_at=NULL WHERE user_id=$1`,
		} {
			if _, err := tx.Exec(ctx, query, deletion.UserID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.account_deletion_audit(user_id,actor_id,auth_version)
			VALUES ($1,$2,$3)`, deletion.UserID, deletion.ActorID, version)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

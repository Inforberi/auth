package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ChangeStatus(ctx context.Context, change domain.StatusChange) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var status domain.Status
		var deleted *time.Time
		err := tx.QueryRow(ctx, `SELECT status,auth_version,deleted_at FROM auth.users WHERE id=$1 FOR UPDATE`, change.UserID).Scan(&status, &version, &deleted)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAccountNotFound
		}
		if err != nil {
			return err
		}
		if deleted != nil {
			return domain.ErrAccountDeleted
		}
		if version != change.ExpectedVersion {
			return domain.ErrAccountConflict
		}
		if err := cancelProtectedRecovery(ctx, tx, change.UserID); err != nil {
			return err
		}
		if status == change.Status {
			return nil
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.users SET status=$2,auth_version=auth_version+1 WHERE id=$1 RETURNING auth_version`, change.UserID, change.Status).Scan(&version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`, change.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.password_resets WHERE user_id=$1`, change.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_verifications v USING auth.user_emails e WHERE v.email_id=e.id AND e.user_id=$1`, change.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth.email_changes SET state='cancelled' WHERE user_id=$1 AND state IN ('pending','completed')`, change.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM auth.email_change_outbox o USING auth.email_changes c WHERE o.change_id=c.id AND c.user_id=$1 AND o.kind='confirm'`, change.UserID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO auth.account_status_audit(user_id,actor_id,previous_status,new_status,auth_version) VALUES ($1,$2,$3,$4,$5)`, change.UserID, change.ActorID, status, change.Status, version)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

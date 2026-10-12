package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ChangeStatus(ctx context.Context, change domain.StatusChange) (domain.AuthVersion, error) {
	var version domain.AuthVersion
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
			return err
		}
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
		if change.Status == domain.StatusActive && status != domain.StatusActive {
			if err := requireAccountActivation(ctx, tx, change.UserID, status); err != nil {
				return err
			}
		}
		if change.Status == domain.StatusBlocked {
			if err := accesspostgres.RequireAdministratorRemains(ctx, tx, change.UserID); err != nil {
				return err
			}
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
		if err := revokeStatusAccess(ctx, tx, change.UserID); err != nil {
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

func revokeStatusAccess(ctx context.Context, tx pgx.Tx, user domain.UserID) error {
	for _, query := range []string{
		`UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL`,
		`DELETE FROM auth.password_resets WHERE user_id=$1`,
		`DELETE FROM auth.temporary_password_credentials WHERE user_id=$1`,
		`DELETE FROM auth.account_invitations WHERE user_id=$1`,
		`DELETE FROM auth.email_verifications v USING auth.user_emails e WHERE v.email_id=e.id AND e.user_id=$1`,
		`UPDATE auth.email_changes SET state='cancelled' WHERE user_id=$1 AND state IN ('pending','completed')`,
		`DELETE FROM auth.email_change_outbox o USING auth.email_changes c WHERE o.change_id=c.id AND c.user_id=$1 AND o.kind='confirm'`,
	} {
		if _, err := tx.Exec(ctx, query, user); err != nil {
			return err
		}
	}
	return nil
}

func requireAccountActivation(ctx context.Context, tx pgx.Tx, user domain.UserID, status domain.Status) error {
	if status == domain.StatusPending {
		return domain.ErrAccountConflict
	}
	var awaiting bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND activated_at IS NULL)`, user).Scan(&awaiting); err != nil {
		return err
	}
	if awaiting {
		return domain.ErrAccountConflict
	}
	return nil
}

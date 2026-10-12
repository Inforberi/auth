package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// LockAccessChanges must precede user/session row locks. Reads and login never acquire it.
func LockAccessChanges(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(734013981)`)
	return err
}

// RequireAdministratorRemains requires LockAccessChanges in the same Read Committed transaction.
func RequireAdministratorRemains(ctx context.Context, tx pgx.Tx, target accountdomain.UserID) error {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
		WHERE ur.user_id=$1 AND r.key='super_admin' AND r.system
	) OR EXISTS (
		SELECT 1 FROM auth.roles r JOIN auth.user_roles ur ON ur.role_id=r.id
		JOIN auth.users u ON u.id=ur.user_id
		WHERE r.key='super_admin' AND r.system AND u.id<>$1
		AND u.status='active' AND u.deleted_at IS NULL
	)`, target).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return accountdomain.ErrLastAdministrator
	}
	return nil
}

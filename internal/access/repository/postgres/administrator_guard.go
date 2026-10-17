package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// LockAccessChanges precedes user/session locks. Public login and ordinary reads do not acquire it.
func LockAccessChanges(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(734013981)`)
	return err
}

// LockAccessSnapshot permits concurrent issuance, but excludes role/assignment mutations until commit.
// Like LockAccessChanges, it must precede user/session locks in a Read Committed transaction.
func LockAccessSnapshot(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(734013981)`)
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
		AND EXISTS(SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key='access.assignments.manage')
		AND `+usableAdministrator+`
	)`, target).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return accountdomain.ErrLastAdministrator
	}
	return nil
}

// RequireUsableAdministrator shares the Access lock with role/status mutations.
func RequireUsableAdministrator(ctx context.Context, tx pgx.Tx) error {
	var ready bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM auth.roles r JOIN auth.user_roles ur ON ur.role_id=r.id
		JOIN auth.users u ON u.id=ur.user_id
		WHERE r.key='super_admin' AND r.system
		AND EXISTS(SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key='access.assignments.manage')
		AND `+usableAdministrator+`)`).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return accountdomain.ErrLastAdministrator
	}
	return nil
}

// This is local credential readiness, not proof that mail delivery or a human-held factor is available.
const usableAdministrator = `u.status='active' AND u.deleted_at IS NULL
	AND EXISTS(SELECT 1 FROM auth.password_credentials p JOIN auth.user_emails e
		ON e.id=p.email_id AND e.user_id=p.user_id WHERE p.user_id=u.id AND e.verified_at IS NOT NULL)
	AND EXISTS(SELECT 1 FROM auth.mfa_totp m WHERE m.user_id=u.id)
	AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials t WHERE t.user_id=u.id)
	AND NOT EXISTS(SELECT 1 FROM auth.account_provisions p WHERE p.user_id=u.id AND (p.activated_at IS NULL OR p.password_change_required))`

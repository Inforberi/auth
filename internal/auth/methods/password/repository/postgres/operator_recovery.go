package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

const operatorRecoveryTargetQuery = `SELECT current_database(),session_user::text,u.status,u.auth_version
	FROM auth.users u JOIN auth.password_credentials p ON p.user_id=u.id
	WHERE u.id=$1 AND u.deleted_at IS NULL AND u.status IN ('active','blocked')
	AND EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
		WHERE ur.user_id=u.id AND r.key='super_admin' AND r.system)
	AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='auth_recovery_operator'
		AND pg_catalog.pg_has_role(session_user,r.oid,'MEMBER'))`

func (r *PasswordRepo) OperatorRecoveryTarget(ctx context.Context, user accountdomain.UserID) (*service.OperatorRecoveryTarget, error) {
	var target service.OperatorRecoveryTarget
	err := r.db.QueryRow(ctx, operatorRecoveryTargetQuery, user).Scan(&target.Database, &target.Operator, &target.Status, &target.AuthVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrOperatorRecoveryDenied
	}
	if err != nil {
		return nil, err
	}
	return &target, nil
}

func (r *PasswordRepo) ResetAdministratorPassword(ctx context.Context, request domain.OperatorRecovery, hash string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; commit closes the transaction.
	}()
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return 0, err
	}
	var target service.OperatorRecoveryTarget
	err = tx.QueryRow(ctx, operatorRecoveryTargetQuery+` FOR UPDATE OF u`, request.UserID).Scan(&target.Database, &target.Operator, &target.Status, &target.AuthVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrOperatorRecoveryDenied
	}
	if err != nil {
		return 0, err
	}
	if target.AuthVersion != request.ExpectedVersion {
		return 0, domain.ErrOperatorRecoveryConflict
	}
	result, err := tx.Exec(ctx, `UPDATE auth.password_credentials SET password_hash=$2 WHERE user_id=$1`, request.UserID, hash)
	if err != nil {
		return 0, err
	}
	if result.RowsAffected() != 1 {
		return 0, domain.ErrOperatorRecoveryDenied
	}
	if err := invalidatePasswordSessions(ctx, tx, request.UserID); err != nil {
		return 0, err
	}
	for _, query := range []string{
		`DELETE FROM auth.mfa_enrollments WHERE user_id=$1`,
		`DELETE FROM auth.mfa_login_challenges WHERE user_id=$1`,
		`DELETE FROM auth.email_login_challenges WHERE user_id=$1`,
		`DELETE FROM auth.email_bindings WHERE user_id=$1`,
	} {
		if _, err := tx.Exec(ctx, query, request.UserID); err != nil {
			return 0, err
		}
	}
	version := target.AuthVersion + 1
	if _, err := tx.Exec(ctx, `INSERT INTO auth.password_audit(user_id,event,auth_version,operator_name,environment,reason)
		VALUES($1,'operator_password_reset',$2,$3,$4,$5)`, request.UserID, version, target.Operator, request.Environment, request.Reason); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return version, nil
}

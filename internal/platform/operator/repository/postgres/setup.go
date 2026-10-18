package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

func (r *Repository) CheckSetupOpen(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var open bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NULL)`, r.realm).Scan(&open)
	if err != nil {
		return setupError(ctx, err)
	}
	if !open {
		return accountdomain.ErrSetupClosed
	}
	return setupError(ctx, r.setup.CheckSetupOpen(ctx))
}

func (r *Repository) SaveSetup(ctx context.Context, operator, request string, payload []byte) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.CheckSetupOpen(ctx); err != nil {
		return time.Time{}, err
	}
	expires, err := r.setup.SaveSetup(ctx, operator, request, payload)
	return expires, setupError(ctx, err)
}

func (r *Repository) CompleteSetup(ctx context.Context, operator, request string, check accountservice.SetupCheck) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return setupError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; preserve its original error.
	}()
	// Same order as Auth setup/access mutations; never take the realm lock first.
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return setupError(ctx, err)
	}
	var open bool
	if err := tx.QueryRow(ctx, `SELECT initialized_at IS NULL FROM platform.operator_realm WHERE id=$1 FOR UPDATE`, r.realm).Scan(&open); err != nil {
		return setupError(ctx, err)
	}
	if !open {
		return accountdomain.ErrSetupClosed
	}
	account, rejected, err := accountpostgres.CompleteSetupInTransaction(ctx, tx, operator, request, check)
	if err != nil {
		return setupError(ctx, err)
	}
	if !rejected {
		permissions := domain.OwnerPermissions()
		if _, err := tx.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) SELECT $1,unnest($2::text[])`, account.UserID, permissions); err != nil {
			return setupError(ctx, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform.operator_audit(actor_id,event,permissions) VALUES($1,'owner_initialized',$2)`, account.UserID, permissions); err != nil {
			return setupError(ctx, err)
		}
		if _, err := tx.Exec(ctx, `UPDATE platform.operator_realm SET initialized_at=clock_timestamp(),first_operator_id=$2 WHERE id=$1`, r.realm, account.UserID); err != nil {
			return setupError(ctx, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return setupError(ctx, err)
	}
	if rejected {
		return accountdomain.ErrSetupInvalid
	}
	return nil
}

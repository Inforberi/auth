package postgres

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func executeRoleTransaction(ctx context.Context, project RoleProjectDatabase, until time.Time, used *atomic.Bool, apply func(context.Context, pgx.Tx) error) error {
	if !time.Now().Before(until) {
		return domain.ErrAdmissionExpired
	}
	if project == nil || used == nil || !used.CompareAndSwap(false, true) {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	tx, err := project.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the mutation/commit result.
	}()
	millis := time.Until(until).Milliseconds()
	if millis < 1 {
		return domain.ErrAdmissionExpired
	}
	_, err = tx.Exec(ctx, `SELECT set_config('transaction_timeout',$1,true),set_config('statement_timeout',$1,true)`, strconv.FormatInt(millis, 10))
	if err != nil {
		return catalogError(ctx, err)
	}
	if err := apply(ctx, tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(domain.ErrAdmissionExpired, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(domain.ErrRoleOutcomeUnknown, ctx.Err())
	}
	return nil
}

package postgres

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type ProjectDatabase interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func executeProjectTransaction(ctx context.Context, project ProjectDatabase, until time.Time, used *atomic.Bool, apply func(context.Context, pgx.Tx) error) error {
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
		return sqlerrors.Catalog(ctx, err)
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
		return sqlerrors.Catalog(ctx, err)
	}
	if err := apply(ctx, tx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(domain.ErrAdmissionExpired, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(domain.ErrOperationOutcomeUnknown, ctx.Err())
	}
	return nil
}

func withProjectRuntime[T any](ctx context.Context, registry *projectruntime.Registry, key projectruntime.Key, until time.Time, execute func(context.Context, projectruntime.Database) (T, error)) (T, error) {
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	var result T
	err := registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		var err error
		result, err = execute(ctx, db)
		return err
	})
	return result, err
}

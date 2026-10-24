package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func (r *RuntimeRoles) readDirectory(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget, read func(context.Context, pgx.Tx) error) error {
	if r.registry == nil {
		return domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	key := projectruntime.Key{Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
	guard := func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		binding, _, err := lockRoleTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		if key.Binding.ProjectID != "" && key.Binding != binding {
			return domain.ErrConflict
		}
		key.Binding = binding
		return nil
	}
	if err := r.mutate(ctx, actor, operatordomain.AccessManage, guard); err != nil {
		return err
	}
	err := r.registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		tx, err := db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return catalogError(ctx, err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the read error; never write project state.
		}()
		if err := checkProjectRuntime(ctx, tx, key.Binding); err != nil {
			return err
		}
		if err := read(ctx, tx); err != nil {
			return err
		}
		return catalogError(ctx, tx.Commit(ctx))
	})
	if err != nil {
		return err
	}
	// Revocation or rebinding during the project read must discard the result.
	return r.mutate(ctx, actor, operatordomain.AccessManage, guard)
}

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

// RuntimeKey is the validated operation locator; it contains no connection credentials.
func (j *RoleReceiptSource) RuntimeKey() projectruntime.Key { return j.key }

func (j *RoleReceiptSource) ReadReceipt(ctx context.Context, db ProjectDatabase) (bool, error) {
	j.read, j.found, j.snapshot = false, false, nil
	tx, err := db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, sqlerrors.Catalog(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Receipt lookup never writes to the project.
	}()
	if err := schemapostgres.CheckRuntime(ctx, tx, j.key.Binding); err != nil {
		return false, err
	}
	snapshot, admission, found, err := j.receipt(ctx, tx, j.actor)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, sqlerrors.Catalog(ctx, err)
	}
	j.snapshot, j.admission, j.found, j.read = snapshot, admission, found, true
	return found, nil
}

func (j *RoleReceiptSource) RecordReceipt(ctx context.Context) error {
	if !j.read || !j.found {
		return domain.ErrConflict
	}
	if err := j.repository.requireRoleAdmission(ctx, j.operation, j.admission); err != nil {
		return err
	}
	return j.repository.recordRoleSnapshot(ctx, j.operation, j.admission, j.action, j.snapshot)
}

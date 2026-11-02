package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

// CheckRuntimeConnection attests each newly authenticated physical connection.
// Mutation writers still check their actual transaction; a cold probe is not authority.
func CheckRuntimeConnection(ctx context.Context, conn *pgx.Conn, binding credentials.Binding) error {
	if conn == nil {
		return domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Failed probes are never returned to a caller.
	}()
	if err := CheckRuntime(ctx, tx, binding); err != nil {
		return err
	}
	return sqlerrors.Catalog(ctx, tx.Commit(ctx))
}

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
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
		return catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Failed probes are never returned to a caller.
	}()
	if err := checkProjectRuntime(ctx, tx, binding); err != nil {
		return err
	}
	return catalogError(ctx, tx.Commit(ctx))
}

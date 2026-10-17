package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func (r *Repository) LogoutRefresh(ctx context.Context, binding service.RefreshBinding, verifier string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; preserve the original error.
	}()
	if err := accesspostgres.LockAccessSnapshot(ctx, tx); err != nil {
		return err
	}
	state, err := lockRefresh(ctx, tx, verifier)
	if err != nil {
		return err
	}
	if state.UserID != binding.Actor.UserID || state.Family.SessionID != binding.SessionID || state.LedgerHash != binding.Actor.TokenHash {
		return domain.ErrInvalidRefresh
	}
	result, err := tx.Exec(ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp()
		WHERE id=$1 AND credential_profile='api' AND revoked_at IS NULL`, binding.SessionID)
	if err != nil {
		return err
	}
	family, err := tx.Exec(ctx, `UPDATE auth.refresh_families SET revoked_at=clock_timestamp()
		WHERE session_id=$1 AND revoked_at IS NULL`, binding.SessionID)
	if err != nil {
		return err
	}
	if result.RowsAffected()+family.RowsAffected() > 0 {
		if err := auditRefresh(ctx, tx, state.UserID, state.Family, "logged_out"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

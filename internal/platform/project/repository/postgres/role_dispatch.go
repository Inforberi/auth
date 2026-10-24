package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// A pool or a leased connection can start the project-owned transaction.
type RoleProjectDatabase interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

// Execute requires a borrowed pool already cold-attested for this project.
// Admission is final authorization: later platform revoke cannot undo this write.
func (a *AdmittedRoleCreation) Execute(ctx context.Context, project RoleProjectDatabase, permissions settings.Catalog, mfaReady bool) (domain.RoleCreationResult, error) {
	if a == nil || a.repository == nil || a.used == nil || !a.actor.Valid() || !time.Now().Before(a.until) {
		return domain.RoleCreationResult{}, domain.ErrAdmissionExpired
	}
	if project == nil || !a.used.CompareAndSwap(false, true) {
		return domain.RoleCreationResult{}, domain.ErrConflict
	}
	ctx, cancel := context.WithDeadline(ctx, a.until)
	defer cancel()
	tx, err := project.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.RoleCreationResult{}, catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Caller result is known only after Commit; preserve it.
	}()
	millis := time.Until(a.until).Milliseconds()
	if millis < 1 {
		return domain.RoleCreationResult{}, domain.ErrAdmissionExpired
	}
	// Bound server work even if cancellation/connection close cannot reach it.
	_, err = tx.Exec(ctx, `SELECT set_config('transaction_timeout',$1,true),set_config('statement_timeout',$1,true)`, strconv.FormatInt(millis, 10))
	if err != nil {
		return domain.RoleCreationResult{}, catalogError(ctx, err)
	}
	result, err := CreatePlatformRoleInTransaction(ctx, tx, a.actor, a.binding, a.command, permissions, mfaReady)
	if err != nil {
		return domain.RoleCreationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return domain.RoleCreationResult{}, errors.Join(domain.ErrAdmissionExpired, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RoleCreationResult{}, errors.Join(domain.ErrRoleOutcomeUnknown, ctx.Err())
	}
	result.CatalogRecorded = a.recordOutcome(ctx, result.Role) == nil
	return result, nil
}

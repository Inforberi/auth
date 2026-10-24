package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

// ReconcileRoleOutcome reads an existing receipt; it cannot create a role or
// admission. A final guarded read prevents disclosure after authority changes.
func (r *Repository) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID, registry *projectruntime.Registry) (domain.RoleOutcome, error) {
	known, err := r.ReadRoleOutcome(ctx, actor, project, operation)
	if err != nil || known.Committed {
		return known, err
	}
	if registry == nil {
		return domain.RoleOutcome{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	job, err := r.roleRecoverySource(ctx, actor, project, operation)
	if err != nil {
		return domain.RoleOutcome{}, err
	}
	var snapshot []byte
	var admission domain.ID
	var found bool
	key := job.key
	err = registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		tx, err := db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return catalogError(ctx, err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer stop()
			_ = tx.Rollback(cleanup) //nolint:gosec // Reconciliation never writes to the project.
		}()
		if err := checkProjectRuntime(ctx, tx, job.key.Binding); err != nil {
			return err
		}
		snapshot, admission, found, err = job.receipt(ctx, tx, domain.ID(actor.UserID))
		if err != nil {
			return err
		}
		return catalogError(ctx, tx.Commit(ctx))
	})
	if err != nil {
		return domain.RoleOutcome{}, err
	}
	if found {
		if err := r.requireRoleAdmission(ctx, operation, admission); err != nil {
			return domain.RoleOutcome{}, err
		}
		if err := r.recordRoleSnapshot(ctx, operation, admission, job.action, snapshot); err != nil {
			return domain.RoleOutcome{}, err
		}
	}
	return r.ReadRoleOutcome(ctx, actor, project, operation)
}

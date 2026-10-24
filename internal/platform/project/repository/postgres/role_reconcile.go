package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type roleReconciliation struct {
	command domain.RoleCreation
	binding credentials.Binding
	realm   domain.ID
}

// ReconcileRoleOutcome reads an existing receipt; it cannot create a role or
// admission. A final guarded read prevents disclosure after authority changes.
func (r *Repository) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, operation domain.ID, registry *projectruntime.Registry) (domain.RoleCreationOutcome, error) {
	known, err := r.ReadRoleOutcome(ctx, actor, operation)
	if err != nil || known.Committed {
		return known, err
	}
	if registry == nil {
		return domain.RoleCreationOutcome{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	job, err := r.roleReconciliation(ctx, actor, operation)
	if err != nil {
		return domain.RoleCreationOutcome{}, err
	}
	var result domain.RoleCreationResult
	var admission domain.ID
	var found bool
	key := projectruntime.Key{Binding: job.binding, Version: job.command.ExpectedVersion, Generation: job.command.ExpectedGeneration}
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
		if err := checkProjectRuntime(ctx, tx, job.binding); err != nil {
			return err
		}
		target, err := json.Marshal(job.binding)
		if err != nil {
			return domain.ErrUnavailable
		}
		request, err := json.Marshal(job.command)
		if err != nil {
			return domain.ErrUnavailable
		}
		result, admission, found, err = readRoleReceipt(ctx, tx, job.realm, domain.ID(actor.UserID), job.command, target, request)
		if err != nil {
			return err
		}
		return catalogError(ctx, tx.Commit(ctx))
	})
	if err != nil {
		return domain.RoleCreationOutcome{}, err
	}
	if found {
		if err := r.requireRoleAdmission(ctx, operation, admission); err != nil {
			return domain.RoleCreationOutcome{}, err
		}
		if err := r.recordRoleOutcome(ctx, operation, admission, result.Role); err != nil {
			return domain.RoleCreationOutcome{}, err
		}
	}
	return r.ReadRoleOutcome(ctx, actor, operation)
}

func (r *Repository) roleReconciliation(ctx context.Context, actor operatordomain.Principal, operation domain.ID) (roleReconciliation, error) {
	var job roleReconciliation
	var request []byte
	err := r.db.QueryRow(ctx, `SELECT realm_id::text,request,binding->>'target',binding->>'reservation',
		(binding->>'database_oid')::oid,(binding->>'owner_oid')::oid,(binding->>'runtime_oid')::oid,(binding->>'schema')::int
		FROM platform.project_role_intents
		WHERE operation_id=$1 AND actor_id=$2 AND EXISTS(
			SELECT 1 FROM platform.project_role_admissions a WHERE a.operation_id=$1)`, operation, actor.UserID).Scan(
		&job.realm, &request, &job.binding.StorageTarget, &job.binding.ReservationID,
		&job.binding.DatabaseOID, &job.binding.OwnerOID, &job.binding.RuntimeOID, &job.binding.SchemaVersion,
	)
	if err != nil {
		return job, catalogError(ctx, err)
	}
	if json.Unmarshal(request, &job.command) != nil || job.command.OperationID != operation {
		return job, domain.ErrConflict
	}
	job.binding.RealmID, job.binding.ProjectID = job.realm, job.command.ProjectID
	return job, nil
}

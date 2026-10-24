package postgres

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type roleRecoverySource struct {
	key        projectruntime.Key
	action     domain.RoleAction
	request    []byte
	creation   domain.RoleCreation
	assignment domain.RoleAssignment
}

func (r *Repository) roleRecoverySource(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (roleRecoverySource, error) {
	var job roleRecoverySource
	b := &job.key.Binding
	err := r.db.QueryRow(ctx, `SELECT realm_id::text,request,binding->>'target',binding->>'reservation',
		(binding->>'database_oid')::oid,(binding->>'owner_oid')::oid,(binding->>'runtime_oid')::oid,(binding->>'schema')::int,
		version,generation,COALESCE(request->>'Action','create')
		FROM platform.project_role_intents WHERE operation_id=$1 AND actor_id=$2 AND project_id=$3 AND EXISTS(
		 SELECT 1 FROM platform.project_role_admissions a WHERE a.operation_id=$1)`, operation, actor.UserID, project).Scan(
		&b.RealmID, &job.request, &b.StorageTarget, &b.ReservationID, &b.DatabaseOID, &b.OwnerOID, &b.RuntimeOID, &b.SchemaVersion,
		&job.key.Version, &job.key.Generation, &job.action,
	)
	if err != nil {
		return job, catalogError(ctx, err)
	}
	b.ProjectID = project
	if err := job.validate(project, operation); err != nil {
		return job, err
	}
	return job, nil
}

func (j *roleRecoverySource) validate(project, operation domain.ID) error {
	switch j.action {
	case domain.RoleCreate:
		c := &j.creation
		if json.Unmarshal(j.request, c) != nil || c.OperationID != operation || c.ProjectID != project || c.ExpectedVersion != j.key.Version || c.ExpectedGeneration != j.key.Generation {
			return domain.ErrConflict
		}
	case domain.RoleGrant, domain.RoleRevoke:
		c := &j.assignment
		if json.Unmarshal(j.request, c) != nil || c.OperationID != operation || c.ProjectID != project || c.Action != j.action || c.ExpectedVersion != j.key.Version || c.ExpectedGeneration != j.key.Generation {
			return domain.ErrConflict
		}
		if _, err := c.Normalize(); err != nil {
			return domain.ErrConflict
		}
	default:
		return domain.ErrConflict
	}
	return nil
}

func (j roleRecoverySource) receipt(ctx context.Context, tx pgx.Tx, actor domain.ID) ([]byte, domain.ID, bool, error) {
	target, err := json.Marshal(j.key.Binding)
	if err != nil {
		return nil, "", false, domain.ErrUnavailable
	}
	if j.action == domain.RoleCreate {
		result, admission, found, err := readRoleReceipt(ctx, tx, j.key.Binding.RealmID, actor, j.creation, target, j.request)
		if err != nil || !found {
			return nil, admission, found, err
		}
		snapshot, err := json.Marshal(result.Role)
		return snapshot, admission, true, err
	}
	result, admission, found, err := readAssignmentReceipt(ctx, tx, j.key.Binding.RealmID, actor, j.assignment, target, j.request)
	if err != nil || !found {
		return nil, admission, found, err
	}
	snapshot, err := json.Marshal(result.RoleAssignmentSnapshot)
	return snapshot, admission, true, err
}

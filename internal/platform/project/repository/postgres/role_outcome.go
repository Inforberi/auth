package postgres

import (
	"context"
	"encoding/json"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// This is completion evidence, not a second authorization or project write.
func (a *AdmittedRoleCreation) recordOutcome(ctx context.Context, result domain.RoleCreationResult) error {
	return a.repository.recordRoleOutcome(ctx, a.command.OperationID, result.ReceiptAdmissionID, result.Role)
}

func (r *Repository) recordRoleOutcome(ctx context.Context, operation, admission domain.ID, role accessdomain.Role) error {
	snapshot, err := json.Marshal(role)
	if err != nil {
		return domain.ErrUnavailable
	}
	return r.recordRoleSnapshot(ctx, operation, admission, domain.RoleCreate, snapshot)
}

func (r *Repository) recordAssignmentOutcome(ctx context.Context, operation, admission domain.ID, result domain.RoleAssignmentSnapshot) error {
	snapshot, err := json.Marshal(result)
	if err != nil {
		return domain.ErrUnavailable
	}
	return r.recordRoleSnapshot(ctx, operation, admission, result.Action, snapshot)
}

func (r *Repository) recordRoleSnapshot(ctx context.Context, operation, admission domain.ID, action domain.RoleAction, snapshot []byte) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `INSERT INTO platform.project_role_outcomes(operation_id,admission_id,role_snapshot)
		SELECT $1,$2,$3::jsonb FROM platform.project_role_intents
		WHERE operation_id=$1 AND COALESCE(request->>'Action','create')=$4
		ON CONFLICT(operation_id) DO NOTHING`, operation, admission, snapshot, action)
	if err != nil {
		return catalogError(ctx, err)
	}
	var same bool
	err = r.db.QueryRow(ctx, `SELECT role_snapshot=$2::jsonb FROM platform.project_role_outcomes WHERE operation_id=$1`, operation, snapshot).Scan(&same)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !same {
		return domain.ErrConflict
	}
	return nil
}

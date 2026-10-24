package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// ReadRoleOutcome requires current project-read authority and returns only the
// caller's own operation. Losing write authority does not erase its history.
func (r *Repository) ReadRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleOutcome, error) {
	if !domain.ValidID(project) || !domain.ValidID(operation) {
		return domain.RoleOutcome{}, domain.ErrInvalidProject
	}
	var result domain.RoleOutcome
	err := r.mutate(ctx, actor, operatordomain.ProjectsRead, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var snapshot []byte
		err := tx.QueryRow(ctx, `SELECT i.operation_id::text,i.project_id::text,o.role_snapshot,COALESCE(i.request->>'Action','create')
			FROM platform.project_role_intents i LEFT JOIN platform.project_role_outcomes o USING(operation_id)
			WHERE i.operation_id=$1 AND i.actor_id=$2 AND i.project_id=$3`, operation, actor.UserID, project).Scan(&result.OperationID, &result.ProjectID, &snapshot, &result.Action)
		if err != nil {
			return catalogError(ctx, err)
		}
		if result.Action != domain.RoleCreate && result.Action != domain.RoleGrant && result.Action != domain.RoleRevoke {
			return domain.ErrConflict
		}
		if len(snapshot) != 0 {
			if err := decodeRoleOutcome(snapshot, &result); err != nil {
				return domain.ErrUnavailable
			}
			result.Committed = true
		}
		return nil
	})
	if err != nil {
		return domain.RoleOutcome{}, err
	}
	return result, nil
}

func decodeRoleOutcome(snapshot []byte, result *domain.RoleOutcome) error {
	switch result.Action {
	case domain.RoleCreate:
		return json.Unmarshal(snapshot, &result.Role)
	case domain.RoleGrant, domain.RoleRevoke:
		var assignment domain.RoleAssignmentSnapshot
		if json.Unmarshal(snapshot, &assignment) != nil || assignment.Action != result.Action || assignment.UserID == "" || assignment.AccessVersion < 1 {
			return domain.ErrConflict
		}
		result.Role, result.UserID, result.AccessVersion, result.Changed = assignment.Role, assignment.UserID, assignment.AccessVersion, assignment.Changed
		return nil
	default:
		return domain.ErrConflict
	}
}

func (r *Repository) requireRoleAdmission(ctx context.Context, operation, admission domain.ID) error {
	var found int
	err := r.db.QueryRow(ctx, `SELECT 1 FROM platform.project_role_admissions WHERE operation_id=$1 AND admission_id=$2`, operation, admission).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	return catalogError(ctx, err)
}

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
func (r *Repository) ReadRoleOutcome(ctx context.Context, actor operatordomain.Principal, operation domain.ID) (domain.RoleCreationOutcome, error) {
	if !domain.ValidID(operation) {
		return domain.RoleCreationOutcome{}, domain.ErrInvalidProject
	}
	var result domain.RoleCreationOutcome
	err := r.mutate(ctx, actor, operatordomain.ProjectsRead, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var snapshot []byte
		err := tx.QueryRow(ctx, `SELECT i.operation_id::text,i.project_id::text,o.role_snapshot
			FROM platform.project_role_intents i LEFT JOIN platform.project_role_outcomes o USING(operation_id)
			WHERE i.operation_id=$1 AND i.actor_id=$2`, operation, actor.UserID).Scan(&result.OperationID, &result.ProjectID, &snapshot)
		if err != nil {
			return catalogError(ctx, err)
		}
		if len(snapshot) != 0 {
			if err := json.Unmarshal(snapshot, &result.Role); err != nil {
				return domain.ErrUnavailable
			}
			result.Committed = true
		}
		return nil
	})
	if err != nil {
		return domain.RoleCreationOutcome{}, err
	}
	return result, nil
}

func (r *Repository) requireRoleAdmission(ctx context.Context, operation, admission domain.ID) error {
	var found int
	err := r.db.QueryRow(ctx, `SELECT 1 FROM platform.project_role_admissions WHERE operation_id=$1 AND admission_id=$2`, operation, admission).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	return catalogError(ctx, err)
}

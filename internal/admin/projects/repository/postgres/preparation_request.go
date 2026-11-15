package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
)

func (r *Repository) RequestPreparation(ctx context.Context, actor operators.Principal, input domain.PreparationRequest) (domain.PreparationOperation, error) {
	if !domain.ValidID(input.ProjectID) || !domain.ValidID(input.OperationID) || input.ExpectedVersion < 1 || input.ExpectedGeneration < 1 {
		return domain.PreparationOperation{}, domain.ErrInvalidProject
	}
	var result domain.PreparationOperation
	err := r.mutate(ctx, actor, operators.ProjectsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var version, generation int64
		var state domain.DesiredState
		err := tx.QueryRow(ctx, `SELECT version,generation,desired_state,phase
			FROM platform.projects WHERE id=$1 FOR UPDATE`, input.ProjectID).Scan(&version, &generation, &state, &result.Phase)
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var matches bool
		err = tx.QueryRow(ctx, `SELECT project_id=$2 AND actor_id=$3 AND expected_version=$4 AND expected_generation=$5,stage
			FROM platform.project_preparation_requests WHERE operation_id=$1`, input.OperationID, input.ProjectID, actor.UserID, input.ExpectedVersion, input.ExpectedGeneration).Scan(&matches, &result.Stage)
		if err == nil {
			if !matches {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return sqlerrors.Catalog(ctx, err)
		}
		if version != input.ExpectedVersion || generation != input.ExpectedGeneration || state != domain.Enabled || result.Phase != domain.Pending {
			return domain.ErrConflict
		}
		err = tx.QueryRow(ctx, `INSERT INTO platform.project_preparation_requests(operation_id,project_id,actor_id,expected_version,expected_generation)
			VALUES($1,$2,$3,$4,$5)
			ON CONFLICT DO NOTHING RETURNING stage`, input.OperationID, input.ProjectID, actor.UserID, input.ExpectedVersion, input.ExpectedGeneration).Scan(&result.Stage)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		return sqlerrors.Catalog(ctx, err)
	})
	result.ProjectID, result.OperationID, result.Version, result.Generation = input.ProjectID, input.OperationID, input.ExpectedVersion, input.ExpectedGeneration
	return result, err
}

func (r *Repository) ReadPreparation(ctx context.Context, actor operators.Principal, project, operation domain.ID) (domain.PreparationOperation, error) {
	if !domain.ValidID(project) || !domain.ValidID(operation) {
		return domain.PreparationOperation{}, domain.ErrInvalidProject
	}
	var result domain.PreparationOperation
	err := r.mutate(ctx, actor, operators.ProjectsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		err := tx.QueryRow(ctx, `SELECT req.operation_id,req.project_id,req.expected_version,req.expected_generation,req.stage,p.phase
			FROM platform.project_preparation_requests req JOIN platform.projects p ON p.id=req.project_id
			WHERE req.project_id=$1 AND req.operation_id=$2`, project, operation).
			Scan(&result.OperationID, &result.ProjectID, &result.Version, &result.Generation, &result.Stage, &result.Phase)
		return sqlerrors.Catalog(ctx, err)
	})
	return result, err
}

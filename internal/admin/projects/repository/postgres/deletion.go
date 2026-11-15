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

func (r *Repository) ConfirmDeletion(ctx context.Context, actor operators.Principal, input domain.DeletionRequest) (domain.DeletionOperation, error) {
	if err := input.Validate(); err != nil {
		return domain.DeletionOperation{}, err
	}
	result := domain.DeletionOperation{ProjectID: input.Target.ProjectID, OperationID: input.OperationID}
	err := r.mutate(ctx, actor, operators.OperatorsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		if err := requireDeletionOwner(ctx, tx, actor); err != nil {
			return err
		}
		var phase domain.Phase
		if err := tx.QueryRow(ctx, `SELECT phase FROM platform.projects WHERE id=$1 FOR UPDATE`, input.Target.ProjectID).Scan(&phase); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var match bool
		err := tx.QueryRow(ctx, `SELECT stage,project_id=$2 AND actor_id=$3 AND version=$4::bigint+1 AND generation=$5::bigint+1 AND acknowledge_users=$6
			FROM platform.project_deletions WHERE operation_id=$1`, input.OperationID, input.Target.ProjectID, actor.UserID,
			input.Target.ExpectedVersion, input.Target.ExpectedGeneration, input.AcknowledgeUsers).Scan(&result.Stage, &match)
		if err == nil {
			if !match {
				return domain.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return sqlerrors.Catalog(ctx, err)
		}
		if phase != domain.Ready {
			return domain.ErrInvalidTransition
		}
		receipt, err := Transition(ctx, tx, domain.Transition{
			ProjectID: input.Target.ProjectID, OperationID: input.OperationID, ExpectedVersion: input.Target.ExpectedVersion,
			ExpectedGeneration: input.Target.ExpectedGeneration, Action: domain.Suspend, ActorKind: domain.OperatorActor, ActorID: domain.ID(actor.UserID), Reason: "confirmed project deletion",
		})
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO platform.project_deletions(operation_id,project_id,actor_id,version,generation,acknowledge_users)
			VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING stage`,
			input.OperationID, input.Target.ProjectID, actor.UserID, receipt.Version, receipt.Generation, input.AcknowledgeUsers).Scan(&result.Stage)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		return sqlerrors.Catalog(ctx, err)
	})
	return result, err
}

func requireDeletionOwner(ctx context.Context, tx pgx.Tx, actor operators.Principal) error {
	var owner bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.operator_realm WHERE initialized_at IS NOT NULL AND first_operator_id=$1)`, actor.UserID).Scan(&owner); err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !owner {
		return operators.ErrForbidden
	}
	return nil
}

func (r *Repository) ReadDeletion(ctx context.Context, actor operators.Principal, project, operation domain.ID) (domain.DeletionOperation, error) {
	result := domain.DeletionOperation{ProjectID: project, OperationID: operation}
	if !domain.ValidID(project) || !domain.ValidID(operation) {
		return result, domain.ErrInvalidProject
	}
	err := r.mutate(ctx, actor, operators.OperatorsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		if err := requireDeletionOwner(ctx, tx, actor); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT stage
			FROM platform.project_deletions WHERE project_id=$1 AND operation_id=$2`, project, operation).Scan(&result.Stage)
		return sqlerrors.Catalog(ctx, err)
	})
	return result, err
}

func guardDeletion(ctx context.Context, tx pgx.Tx, project domain.ID) error {
	var blocked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.project_deletions WHERE project_id=$1
    AND stage IN ('confirmed','draining','verified','deleted'))`, project).Scan(&blocked)
	if err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if blocked {
		return domain.ErrConflict
	}
	return nil
}

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// Transition joins the caller's transaction, after its authority locks.
// Caller must rollback on error and commit before returning the receipt to a client.
func Transition(ctx context.Context, tx pgx.Tx, command domain.Transition) (domain.TransitionReceipt, error) {
	if err := command.Validate(); err != nil {
		return domain.TransitionReceipt{}, err
	}
	if tx == nil {
		return domain.TransitionReceipt{}, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var current domain.Project
	var bindingPresent bool
	err := tx.QueryRow(ctx, `SELECT desired_state,phase,version,generation,
		database_name IS NOT NULL AND credential_ref IS NOT NULL AND schema_version>0
		FROM platform.projects WHERE id=$1 FOR UPDATE`, command.ProjectID).Scan(
		&current.DesiredState, &current.Phase, &current.Version, &current.Generation, &bindingPresent,
	)
	if err != nil {
		return domain.TransitionReceipt{}, catalogError(ctx, err)
	}
	if receipt, found, err := replayTransition(ctx, tx, command); found || err != nil {
		return receipt, err
	}
	if current.Version != command.ExpectedVersion || current.Generation != command.ExpectedGeneration {
		return domain.TransitionReceipt{}, domain.ErrConflict
	}
	next, err := current.Next(command.Action)
	if err != nil {
		return domain.TransitionReceipt{}, err
	}
	// Binding metadata is necessary, not sufficient proof of real storage readiness.
	if command.Action == domain.FinishPreparation && !bindingPresent {
		return domain.TransitionReceipt{}, domain.ErrInvalidTransition
	}
	var result domain.TransitionReceipt
	result.ProjectID = command.ProjectID
	err = tx.QueryRow(ctx, `WITH changed AS (
		UPDATE platform.projects SET desired_state=$2,phase=$3,version=version+1,generation=generation+1,
		updated_at=GREATEST(updated_at,clock_timestamp()) WHERE id=$1 AND version=$4 AND generation=$5
		RETURNING desired_state,phase,version,generation
	) INSERT INTO platform.project_events(project_id,operation_id,action,actor_kind,actor_id,reason,
		from_state,from_phase,from_version,from_generation,to_state,to_phase,to_version,to_generation)
		SELECT $1,$6,$7,$8,$9,$10,$11,$12,$4,$5,desired_state,phase,version,generation FROM changed
		RETURNING to_state,to_phase,to_version,to_generation`,
		command.ProjectID, next.DesiredState, next.Phase, current.Version, current.Generation,
		command.OperationID, command.Action, command.ActorKind, command.ActorID, command.Reason, current.DesiredState, current.Phase).
		Scan(&result.DesiredState, &result.Phase, &result.Version, &result.Generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TransitionReceipt{}, domain.ErrConflict
	}
	if err != nil {
		return domain.TransitionReceipt{}, catalogError(ctx, err)
	}
	return result, nil
}

func replayTransition(ctx context.Context, tx pgx.Tx, command domain.Transition) (domain.TransitionReceipt, bool, error) {
	result := domain.TransitionReceipt{ProjectID: command.ProjectID, Replayed: true}
	var matches bool
	err := tx.QueryRow(ctx, `SELECT action=$3 AND actor_kind=$4 AND actor_id=$5 AND reason=$6 AND from_version=$7 AND from_generation=$8,
		to_state,to_phase,to_version,to_generation FROM platform.project_events WHERE project_id=$1 AND operation_id=$2`,
		command.ProjectID, command.OperationID, command.Action, command.ActorKind, command.ActorID, command.Reason,
		command.ExpectedVersion, command.ExpectedGeneration).Scan(&matches, &result.DesiredState, &result.Phase, &result.Version, &result.Generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TransitionReceipt{}, false, nil
	}
	if err != nil {
		return domain.TransitionReceipt{}, false, catalogError(ctx, err)
	}
	if !matches {
		return domain.TransitionReceipt{}, true, domain.ErrConflict
	}
	return result, true, nil
}

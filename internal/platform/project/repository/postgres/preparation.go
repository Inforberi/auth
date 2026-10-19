package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// Reserve starts catalog preparation only. No storage DDL runs in this transaction.
func (r *PreparationRepository) Reserve(ctx context.Context, input domain.PreparationRequest) (domain.PreparationReservation, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.CheckRuntime(ctx); err != nil {
		return domain.PreparationReservation{}, err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return domain.PreparationReservation{}, catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Preserve the operation error; Commit closes the transaction.
	}()
	var marker string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL FOR SHARE`, r.realm).Scan(&marker); err != nil {
		return domain.PreparationReservation{}, catalogError(ctx, err)
	}
	receipt, err := Transition(ctx, tx, domain.Transition{
		ProjectID: input.ProjectID, OperationID: input.OperationID, ExpectedVersion: input.ExpectedVersion, ExpectedGeneration: input.ExpectedGeneration,
		Action: domain.BeginPreparation, ActorKind: domain.ProvisionerActor, ActorID: r.realm, Reason: "reserve project storage",
	})
	if err != nil {
		return domain.PreparationReservation{}, err
	}
	// A historical begin receipt is not authority to resume after a newer epoch or a target change.
	var current bool
	err = tx.QueryRow(ctx, `SELECT version=$2 AND generation=$3 AND phase='provisioning' AND storage_target=$4
		AND database_name IS NULL AND credential_ref IS NULL AND schema_version=0 FROM platform.projects WHERE id=$1`,
		input.ProjectID, receipt.Version, receipt.Generation, r.target).Scan(&current)
	if err != nil {
		return domain.PreparationReservation{}, catalogError(ctx, err)
	}
	if !current {
		return domain.PreparationReservation{}, domain.ErrConflict
	}
	var result domain.PreparationReservation
	err = tx.QueryRow(ctx, `SELECT project_id::text,reservation_id::text,storage_target,operation_id::text,version,generation,created_at
		FROM platform.project_preparations WHERE project_id=$1 FOR UPDATE`, input.ProjectID).Scan(
		&result.ProjectID, &result.ReservationID, &result.StorageTarget, &result.OperationID, &result.Version, &result.Generation, &result.CreatedAt,
	)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if receipt.Replayed {
			return domain.PreparationReservation{}, domain.ErrConflict
		}
		if err := requireFirstPreparation(ctx, tx, input); err != nil {
			return domain.PreparationReservation{}, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO platform.project_preparations(project_id,storage_target,operation_id,version,generation)
			VALUES($1,$2,$3,$4,$5) RETURNING project_id::text,reservation_id::text,storage_target,operation_id::text,version,generation,created_at`,
			input.ProjectID, r.target, input.OperationID, receipt.Version, receipt.Generation).Scan(
			&result.ProjectID, &result.ReservationID, &result.StorageTarget, &result.OperationID, &result.Version, &result.Generation, &result.CreatedAt,
		)
	case err != nil:
		return domain.PreparationReservation{}, catalogError(ctx, err)
	case result.StorageTarget != r.target:
		return domain.PreparationReservation{}, domain.ErrConflict
	case receipt.Replayed:
		if result.OperationID != input.OperationID || result.Version != receipt.Version || result.Generation != receipt.Generation {
			return domain.PreparationReservation{}, domain.ErrConflict
		}
	default:
		if result.Generation >= receipt.Generation {
			return domain.PreparationReservation{}, domain.ErrConflict
		}
		_, err = tx.Exec(ctx, `UPDATE platform.project_preparations SET operation_id=$2,version=$3,generation=$4 WHERE project_id=$1`,
			input.ProjectID, input.OperationID, receipt.Version, receipt.Generation)
		result.OperationID, result.Version, result.Generation = input.OperationID, receipt.Version, receipt.Generation
	}
	if err != nil {
		return domain.PreparationReservation{}, catalogError(ctx, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.PreparationReservation{}, catalogError(ctx, err)
	}
	return result, nil
}

func requireFirstPreparation(ctx context.Context, tx pgx.Tx, input domain.PreparationRequest) error {
	var priorAttempt bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.project_events
		WHERE project_id=$1 AND action='begin_preparation' AND operation_id<>$2)`, input.ProjectID, input.OperationID).Scan(&priorAttempt); err != nil {
		return catalogError(ctx, err)
	}
	if priorAttempt {
		return domain.ErrConflict
	}
	return nil
}

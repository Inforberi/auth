package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// WithdrawOnboarding also works after suspend, but cannot revoke a newer preparation epoch.
func (r *PreparationRepository) WithdrawOnboarding(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding) error {
	if !r.matchesSecretsBinding(reservation, binding) || reservation.StorageTarget != r.target {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := r.CheckRuntime(ctx); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return catalogError(ctx, err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup) //nolint:gosec // Do not claim a lost commit response means rollback.
	}()
	var marker string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm WHERE id=$1 FOR SHARE`, r.realm).Scan(&marker); err != nil {
		return catalogError(ctx, err)
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.projects WHERE id=$1 AND storage_target=$2 FOR SHARE`, reservation.ProjectID, r.target).Scan(&marker); err != nil {
		return catalogError(ctx, err)
	}
	var admitted bool
	err = tx.QueryRow(ctx, `SELECT s.onboarding_admitted FROM platform.project_preparations s
		JOIN platform.project_secrets k ON k.project_id=s.project_id
		WHERE s.project_id=$1 AND s.reservation_id=$2 AND s.operation_id=$3 AND s.version=$4 AND s.generation=$5
		AND s.storage_target=$6 AND k.storage_target=s.storage_target AND k.reservation_id=s.reservation_id
		AND k.database_oid=$7 AND k.owner_oid=$8 AND k.runtime_oid=$9 AND k.schema_version=$10 FOR UPDATE OF s`,
		reservation.ProjectID, reservation.ReservationID, reservation.OperationID, reservation.Version, reservation.Generation,
		r.target, binding.DatabaseOID, binding.OwnerOID, binding.RuntimeOID, binding.SchemaVersion).Scan(&admitted)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrConflict
	}
	if err != nil {
		return catalogError(ctx, err)
	}
	if admitted {
		if _, err := tx.Exec(ctx, `UPDATE platform.project_preparations SET onboarding_admitted=false WHERE project_id=$1`, reservation.ProjectID); err != nil {
			return catalogError(ctx, err)
		}
	}
	return catalogError(ctx, tx.Commit(ctx))
}

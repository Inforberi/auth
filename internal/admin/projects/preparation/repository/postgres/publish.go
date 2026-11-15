package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
)

func (r *PreparationRepository) RequestedBinding(ctx context.Context, request domain.PreparationRequest) (domain.PreparationReservation, credentials.Binding, error) {
	var reservation domain.PreparationReservation
	err := r.db.QueryRow(ctx, `SELECT project_id,reservation_id,storage_target,operation_id,version,generation,created_at
		FROM platform.project_preparations WHERE project_id=$1 AND operation_id=$2 AND storage_target=$3 AND secrets_created`,
		request.ProjectID, request.OperationID, r.target).Scan(&reservation.ProjectID, &reservation.ReservationID, &reservation.StorageTarget,
		&reservation.OperationID, &reservation.Version, &reservation.Generation, &reservation.CreatedAt)
	if err != nil {
		return reservation, credentials.Binding{}, sqlerrors.Catalog(ctx, err)
	}
	if err := r.CheckCurrent(ctx, reservation); err != nil {
		return reservation, credentials.Binding{}, err
	}
	stored, err := scanSecret(r.db.QueryRow(ctx, `SELECT `+secretColumns+` FROM platform.project_secrets WHERE project_id=$1`, reservation.ProjectID), r.realm, reservation.ProjectID)
	defer clear(stored.payload)
	return reservation, stored.binding, sqlerrors.Catalog(ctx, err)
}

func (r *PreparationRepository) PublishRequested(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding) error {
	if !r.matchesSecretsBinding(reservation, binding) {
		return domain.ErrConflict
	}
	dbName, _, err := reservation.ResourceNames()
	if err != nil {
		return err
	}
	err = pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		var marker string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL FOR SHARE`, r.realm).Scan(&marker); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if err := tx.QueryRow(ctx, `SELECT id::text FROM platform.projects WHERE id=$1 FOR UPDATE`, reservation.ProjectID).Scan(&marker); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if _, err := r.lockSecretsPreparation(ctx, tx, reservation); err != nil {
			return err
		}
		var finish domain.ID
		if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()`).Scan(&finish); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		tag, err := tx.Exec(ctx, `UPDATE platform.projects SET database_name=$2,credential_ref=$3::uuid::text,schema_version=$4
			WHERE id=$1 AND EXISTS(SELECT 1 FROM platform.project_secrets s WHERE s.project_id=$1
			AND s.reservation_id=$3 AND s.database_oid=$5 AND s.owner_oid=$6 AND s.runtime_oid=$7 AND s.schema_version=$4)`,
			reservation.ProjectID, dbName, reservation.ReservationID, binding.SchemaVersion, binding.DatabaseOID, binding.OwnerOID, binding.RuntimeOID)
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if tag.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		_, err = catalog.Transition(ctx, tx, domain.Transition{
			ProjectID: reservation.ProjectID, OperationID: finish, ExpectedVersion: reservation.Version, ExpectedGeneration: reservation.Generation,
			Action: domain.FinishPreparation, ActorKind: domain.ProvisionerActor, ActorID: r.realm, Reason: "verified managed runtime",
		})
		if err != nil {
			return err
		}
		tag, err = tx.Exec(ctx, `UPDATE platform.project_preparation_requests SET stage='ready' WHERE project_id=$1 AND operation_id=$2
			AND stage='managed_configuration_prepared'`, reservation.ProjectID, reservation.OperationID)
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if tag.RowsAffected() != 1 {
			return domain.ErrConflict
		}
		return nil
	})
	return err
}

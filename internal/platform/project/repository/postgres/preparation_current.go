package postgres

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// CheckCurrent fences offline stages. It is not authority to publish ready or serve traffic.
func (r *PreparationRepository) CheckCurrent(ctx context.Context, reservation domain.PreparationReservation) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var current bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.projects p
		JOIN platform.project_preparations s ON s.project_id=p.id
		WHERE p.id=$1 AND p.version=$2 AND p.generation=$3 AND p.phase='provisioning' AND p.desired_state='enabled'
		AND p.storage_target=$4 AND p.database_name IS NULL AND p.credential_ref IS NULL AND p.schema_version=0
		AND s.reservation_id=$5 AND s.operation_id=$6 AND s.version=p.version AND s.generation=p.generation
		AND s.storage_target=p.storage_target)
		AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$7 AND initialized_at IS NOT NULL)`,
		reservation.ProjectID, reservation.Version, reservation.Generation, r.target, reservation.ReservationID, reservation.OperationID, r.realm).Scan(&current)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !current {
		return domain.ErrConflict
	}
	return nil
}

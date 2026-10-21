package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type OnboardingAdmission struct {
	db          *pgxpool.Pool
	project     domain.Project
	reservation domain.PreparationReservation
	binding     credentials.Binding
}

func NewOnboardingAdmission(db *pgxpool.Pool, project domain.Project, reservation domain.PreparationReservation, binding credentials.Binding) (*OnboardingAdmission, error) {
	if db == nil || !validOnboardingProject(project) || !domain.ValidID(binding.RealmID) || !domain.ValidID(reservation.ReservationID) ||
		!domain.ValidID(reservation.OperationID) || !domain.ValidStorageTarget(binding.StorageTarget) || binding.DatabaseOID == 0 || binding.OwnerOID == 0 || binding.RuntimeOID == 0 || binding.SchemaVersion < 1 ||
		project.ID != reservation.ProjectID || project.ID != binding.ProjectID || reservation.ReservationID != binding.ReservationID ||
		project.Version != reservation.Version || project.Generation != reservation.Generation || reservation.StorageTarget != binding.StorageTarget {
		return nil, domain.ErrConflict
	}
	return &OnboardingAdmission{db: db, project: project, reservation: reservation, binding: binding}, nil
}

func validOnboardingProject(p domain.Project) bool {
	return domain.ValidID(p.ID) && domain.ValidSlug(p.Slug) && domain.ValidOrigin(p.Origin) &&
		p.Version > 0 && p.Generation > 0 && p.DesiredState == domain.Enabled && p.Phase == domain.Provisioning
}

func (a *OnboardingAdmission) Check(ctx context.Context) (bool, error) {
	if a == nil || a.db == nil {
		return false, domain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, catalogError(ctx, err)
	}
	r, b := a.reservation, a.binding
	var allowed bool
	err := a.db.QueryRow(ctx, `SELECT current_user=session_user
		AND NOT has_column_privilege(current_user,'platform.project_secrets','ciphertext','SELECT')
		AND NOT has_column_privilege(current_user,'platform.project_preparations','onboarding_admitted','INSERT,UPDATE')
		AND EXISTS(SELECT 1 `+currentPreparation+` AND s.onboarding_admitted AND s.secrets_created
		AND p.slug=$8 AND p.origin=$9
		AND EXISTS(SELECT 1 FROM platform.project_secrets k WHERE k.project_id=p.id AND k.reservation_id=s.reservation_id
			AND k.storage_target=s.storage_target AND k.database_oid=$10 AND k.owner_oid=$11 AND k.runtime_oid=$12 AND k.schema_version=$13))`,
		r.ProjectID, r.Version, r.Generation, b.StorageTarget, r.ReservationID, r.OperationID, b.RealmID,
		a.project.Slug, a.project.Origin, b.DatabaseOID, b.OwnerOID, b.RuntimeOID, b.SchemaVersion).Scan(&allowed)
	if err != nil {
		return false, catalogError(ctx, err)
	}
	return allowed, nil
}

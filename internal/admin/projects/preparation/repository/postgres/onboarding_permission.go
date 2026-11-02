package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

// PermitOnboarding records a verified SQL runtime, never opens it or publishes normal Auth.
func (r *PreparationRepository) PermitOnboarding(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, runtime *pgxpool.Pool) error {
	return r.withSecrets(ctx, reservation, binding, codec, func(ctx context.Context, tx pgx.Tx, stored secretRecord) error {
		keys, err := codec.OpenOnboarding(binding, stored.version, stored.keyID, stored.payload)
		if err != nil {
			return err
		}
		if err := schemapostgres.CheckOnboardingRuntime(ctx, runtime, keys.Proof()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE platform.project_preparations SET onboarding_admitted=true
			WHERE project_id=$1 AND NOT onboarding_admitted`, reservation.ProjectID)
		return sqlerrors.Catalog(ctx, err)
	})
}

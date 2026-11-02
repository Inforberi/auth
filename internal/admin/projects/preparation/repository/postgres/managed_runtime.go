package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

// ProbeManagedRuntime does not publish ready or admit the first-admin HTTP flow.
func (r *PreparationRepository) ProbeManagedRuntime(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, runtime *pgxpool.Pool) error {
	return r.withSecrets(ctx, reservation, binding, codec, func(ctx context.Context, _ pgx.Tx, stored secretRecord) error {
		keys, err := codec.OpenOnboarding(binding, stored.version, stored.keyID, stored.payload)
		if err != nil {
			return err
		}
		return schemapostgres.CheckManagedRuntime(ctx, runtime, keys.Proof())
	})
}

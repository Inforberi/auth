package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// ProbeManagedRuntime does not publish ready or admit the first-admin HTTP flow.
func (r *PreparationRepository) ProbeManagedRuntime(ctx context.Context, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, runtime *pgxpool.Pool) error {
	return r.withSecrets(ctx, reservation, binding, codec, func(ctx context.Context, _ pgx.Tx, stored secretRecord) error {
		keys, err := codec.OpenOnboarding(binding, stored.version, stored.keyID, stored.payload)
		if err != nil {
			return err
		}
		return CheckManagedRuntime(ctx, runtime, keys.Proof())
	})
}

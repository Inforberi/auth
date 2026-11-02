package preparation

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/storage/postgres"
)

func (input Input) prepareSecrets(ctx context.Context, physical *storage.Target, preparation *preparationpostgres.PreparationRepository, reservation domain.PreparationReservation, codec *credentials.Codec) (string, error) {
	binding, err := physical.SecretsBinding()
	if err != nil {
		return "", err
	}
	if err := preparation.EnsureSecrets(ctx, reservation, binding, codec); err != nil {
		return "", err
	}
	if !input.Password {
		return "secrets_stored", nil
	}
	value, err := preparation.ReadDatabaseCredential(ctx, reservation, binding, codec)
	if err != nil {
		return "", err
	}
	if err := physical.InstallPassword(ctx, value, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) }); err != nil {
		return "", err
	}
	if input.Managed || input.Onboarding {
		proof, err := preparation.ReadSetupProof(ctx, reservation, binding, codec)
		if err != nil {
			return "", err
		}
		prepare, stage := physical.PrepareOnboarding, "onboarding_prepared"
		if input.Managed {
			prepare, stage = physical.PrepareManagedConfiguration, "managed_configuration_prepared"
		}
		if err := prepare(ctx, proof, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) }); err != nil {
			return "", err
		}
		return stage, nil
	}
	return "password_installed", nil
}

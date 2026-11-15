package service

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func (input Input) prepareSecrets(ctx context.Context, physical Physical, preparation Catalog, reservation domain.PreparationReservation, codec *credentials.Codec) (string, error) {
	binding, err := physical.SecretsBinding()
	if err != nil {
		return "", fmt.Errorf("read physical binding: %w", err)
	}
	if err := preparation.EnsureSecrets(ctx, reservation, binding, codec); err != nil {
		return "", fmt.Errorf("store project secrets: %w", err)
	}
	if !input.Password {
		return "secrets_stored", nil
	}
	value, err := preparation.ReadDatabaseCredential(ctx, reservation, binding, codec)
	if err != nil {
		return "", fmt.Errorf("read project database credential: %w", err)
	}
	if err := physical.InstallPassword(ctx, value, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) }); err != nil {
		return "", fmt.Errorf("install project database password: %w", err)
	}
	if input.Managed || input.Onboarding {
		proof, err := preparation.ReadSetupProof(ctx, reservation, binding, codec)
		if err != nil {
			return "", fmt.Errorf("read project setup proof: %w", err)
		}
		prepare, stage := physical.PrepareOnboarding, "onboarding_prepared"
		if input.Managed {
			prepare, stage = physical.PrepareManagedConfiguration, "managed_configuration_prepared"
		}
		if err := prepare(ctx, proof, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) }); err != nil {
			return "", fmt.Errorf("prepare project configuration: %w", err)
		}
		return stage, nil
	}
	return "password_installed", nil
}

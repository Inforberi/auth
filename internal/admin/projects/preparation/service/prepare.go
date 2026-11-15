package service

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

type Catalog interface {
	Reserve(context.Context, domain.PreparationRequest) (domain.PreparationReservation, error)
	CheckCurrent(context.Context, domain.PreparationReservation) error
	EnsureSecrets(context.Context, domain.PreparationReservation, credentials.Binding, *credentials.Codec) error
	ReadDatabaseCredential(context.Context, domain.PreparationReservation, credentials.Binding, *credentials.Codec) (credentials.DatabaseCredential, error)
	ReadSetupProof(context.Context, domain.PreparationReservation, credentials.Binding, *credentials.Codec) (credentials.SetupProof, error)
}

type Physical interface {
	InstallSchema(context.Context, func(context.Context) error) (int, error)
	SecretsBinding() (credentials.Binding, error)
	InstallPassword(context.Context, credentials.DatabaseCredential, func(context.Context) error) error
	PrepareOnboarding(context.Context, credentials.SetupProof, func(context.Context) error) error
	PrepareManagedConfiguration(context.Context, credentials.SetupProof, func(context.Context) error) error
}

func Prepare(ctx context.Context, input Input, catalog Catalog, physical Physical, codec *credentials.Codec, create func(context.Context, domain.PreparationReservation) (uint32, error)) (Result, error) {
	reservation, err := catalog.Reserve(ctx, input.Request)
	if err != nil {
		return Result{}, fmt.Errorf("reserve project storage: %w", err)
	}
	oid, err := create(ctx, reservation)
	if err != nil {
		return Result{}, fmt.Errorf("prepare physical database: %w", err)
	}
	stage, schemaVersion := "database_sealed", 0
	if input.Schema {
		schemaVersion, err = physical.InstallSchema(ctx, func(check context.Context) error { return catalog.CheckCurrent(check, reservation) })
		if err != nil {
			return Result{}, fmt.Errorf("install project schema: %w", err)
		}
		stage = "schema_prepared"
	}
	if input.Secrets {
		stage, err = input.prepareSecrets(ctx, physical, catalog, reservation, codec)
		if err != nil {
			return Result{}, fmt.Errorf("prepare project credentials: %w", err)
		}
	}
	return Result{ProjectID: reservation.ProjectID, Stage: stage, DatabaseOID: oid, SchemaVersion: schemaVersion}, nil
}

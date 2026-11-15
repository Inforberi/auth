package preparation

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpg "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	service "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
)

func activateRequested(ctx context.Context, input service.Input, connections Connections, catalog *preparationpg.PreparationRepository, physical *storage.Target) (service.Result, error) {
	reservation, binding, err := catalog.RequestedBinding(ctx, input.Request)
	if err != nil {
		return service.Result{}, err
	}
	database, owner, err := reservation.ResourceNames()
	if err != nil {
		return service.Result{}, err
	}
	credential, err := catalog.ReadDatabaseCredential(ctx, reservation, binding, connections.Codec)
	if err != nil {
		return service.Result{}, err
	}
	cfg, err := pgxpool.ParseConfig(connections.Storage.ConnString())
	if err != nil {
		return service.Result{}, errors.New("runtime probe configuration failed")
	}
	cfg.ConnConfig = connections.Storage.Copy()
	cfg.ConnConfig.Database = database
	cfg.ConnConfig.User = "authr_" + strings.TrimPrefix(owner, "autho_")
	cfg.ConnConfig.Password = credential.Password()
	cfg.MaxConns, cfg.MinConns, cfg.MinIdleConns = 1, 0, 0
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return service.Result{}, errors.New("runtime probe connection failed")
	}
	defer runtime.Close()
	if err := physical.ActivateManagedRuntime(ctx, reservation, binding, connections.Codec, catalog, runtime); err != nil {
		return service.Result{}, err
	}
	// A lost catalog commit reply is recovered from the persisted ready stage.
	if err := catalog.PublishRequested(ctx, reservation, binding); err != nil {
		return service.Result{}, err
	}
	return service.Result{ProjectID: reservation.ProjectID, Stage: "ready", DatabaseOID: binding.DatabaseOID, SchemaVersion: binding.SchemaVersion}, nil
}

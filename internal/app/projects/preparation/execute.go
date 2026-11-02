package preparation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/storage/postgres"
)

func Run(ctx context.Context, input Input, connections Connections) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, connections.Storage)
	if err != nil {
		return Result{}, errors.New("storage connection failed")
	}
	closeStorage := func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(cleanup) //nolint:gosec // A dedicated connection is never returned to a pool with a held lock.
	}
	defer closeStorage()
	physical, err := storage.New(conn, input.Realm, input.Target)
	if err != nil {
		return Result{}, err
	}
	if err := physical.CheckRuntime(ctx); err != nil {
		return Result{}, err
	}
	poolConfig, err := pgxpool.ParseConfig(connections.Catalog.ConnString())
	if err != nil {
		return Result{}, errors.New("catalog configuration failed")
	}
	poolConfig.ConnConfig = connections.Catalog
	poolConfig.MaxConns, poolConfig.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return Result{}, errors.New("catalog connection failed")
	}
	defer pool.Close()
	preparation, err := preparationpostgres.NewPreparation(pool, input.Realm, input.Target)
	if err != nil {
		return Result{}, err
	}
	reservation, err := preparation.Reserve(ctx, input.Request)
	if err != nil {
		return Result{}, err
	}
	resources, err := physical.Prepare(ctx, reservation)
	if err != nil {
		return Result{}, err
	}
	stage, schemaVersion := "database_sealed", 0
	if input.Schema {
		schemaVersion, err = physical.InstallSchema(ctx, func(check context.Context) error { return preparation.CheckCurrent(check, reservation) })
		if err != nil {
			return Result{}, err
		}
		stage = "schema_prepared"
	}
	if input.Secrets {
		stage, err = input.prepareSecrets(ctx, physical, preparation, reservation, connections.Codec)
		if err != nil {
			return Result{}, err
		}
	}
	closeStorage() // Release the target lock even if the output pipe is blocked.
	return Result{ProjectID: reservation.ProjectID, Stage: stage, DatabaseOID: resources.DatabaseOID, SchemaVersion: schemaVersion}, nil
}

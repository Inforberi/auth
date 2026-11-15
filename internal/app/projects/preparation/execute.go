package preparation

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	storage "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/database/postgres"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	preparationservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/service"
)

func Run(ctx context.Context, input preparationservice.Input, connections Connections) (preparationservice.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, connections.Storage)
	if err != nil {
		return preparationservice.Result{}, errors.New("storage connection failed")
	}
	closeStorage := func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_ = conn.Close(cleanup) //nolint:gosec // A dedicated connection is never returned to a pool with a held lock.
	}
	defer closeStorage()
	physical, err := storage.New(conn, input.Realm, input.Target)
	if err != nil {
		return preparationservice.Result{}, err
	}
	if err := physical.CheckRuntime(ctx); err != nil {
		return preparationservice.Result{}, err
	}
	poolConfig, err := pgxpool.ParseConfig(connections.Catalog.ConnString())
	if err != nil {
		return preparationservice.Result{}, errors.New("catalog configuration failed")
	}
	poolConfig.ConnConfig = connections.Catalog
	poolConfig.MaxConns, poolConfig.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return preparationservice.Result{}, errors.New("catalog connection failed")
	}
	defer pool.Close()
	preparation, err := preparationpostgres.NewPreparation(pool, input.Realm, input.Target)
	if err != nil {
		return preparationservice.Result{}, err
	}
	if input.Requested {
		if err := preparation.CheckRuntime(ctx); err != nil {
			return preparationservice.Result{}, err
		}
		var locked bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('project-preparation:'||$1::text,0))`, input.Request.OperationID).Scan(&locked); err != nil || !locked {
			return preparationservice.Result{}, domain.ErrConflict
		}
		var stage string
		input.Request, stage, err = preparation.ClaimRequested(ctx, input.Request.OperationID)
		if err != nil {
			return preparationservice.Result{}, err
		}
		if stage == "managed_configuration_prepared" {
			return activateRequested(ctx, input, connections, preparation, physical)
		}
	}
	result, err := preparationservice.Prepare(ctx, input, preparation, physical, connections.Codec, func(ctx context.Context, reservation domain.PreparationReservation) (uint32, error) {
		resources, err := physical.Prepare(ctx, reservation)
		return resources.DatabaseOID, err
	})
	if input.Requested {
		stage := result.Stage
		if err != nil {
			stage = "failed"
		}
		report, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		recordErr := preparation.RecordRequestedResult(report, input.Request.OperationID, stage)
		stop()
		if recordErr != nil {
			return preparationservice.Result{}, errors.Join(err, recordErr)
		}
		if err == nil {
			return activateRequested(ctx, input, connections, preparation, physical)
		}
	}
	if err != nil {
		return preparationservice.Result{}, err
	}

	closeStorage() // Release the target lock even if the output pipe is blocked.
	return result, nil
}

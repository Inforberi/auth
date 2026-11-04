package app

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/app/auth"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
)

func openResources(ctx context.Context, cfg *config.Config, owned *auth.Resources) (*pgxpool.Pool, *redis.Client, *zap.Logger, error) {
	log := logger.CreateLogger(cfg.Logger)
	owned.Add(func() {
		if err := log.Sync(); err != nil {
			return // stdout/stderr may not support fsync; no buffered logger remains.
		}
	})
	owned.Add(zap.RedirectStdLog(log))

	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create postgres pool: %w", err)
	}
	owned.Add(pool.Close)
	log.Info("postgres pool created successfully")

	rdb, err := redisclient.New(ctx, cfg.Redis)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init redis: %w", err)
	}
	owned.Add(func() {
		if err := rdb.Close(); err != nil {
			log.Error("failed to close Redis")
		}
	})
	log.Info("redis created successfully")
	return pool, rdb, log, nil
}

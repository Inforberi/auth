package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	httpserver "github.com/Inforberi/financial-intelligence/internal/server/http"
)

// These dependencies are borrowed. Realm cleanup never closes their process owner.
type realmDependencies struct {
	pool  *pgxpool.Pool
	redis *redis.Client
	log   *zap.Logger
	hash  *hasher.Bounded
}

func (d realmDependencies) validate() error {
	if d.pool == nil || d.redis == nil || d.log == nil || d.hash == nil {
		return errors.New("auth realm requires pool, Redis, logger and shared hasher")
	}
	return nil
}

func New(ctx context.Context, cfg *config.Config) (_ *App, err error) {
	owned := &resources{}
	defer func() {
		if err != nil {
			owned.close()
		}
	}()
	pool, rdb, log, err := owned.open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Capacity.HashConcurrency < 1 {
		return nil, errors.New("password hash concurrency must be positive")
	}
	deps := realmDependencies{
		pool: pool, redis: rdb, log: log,
		hash: hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), cfg.Capacity.HashConcurrency),
	}
	assembled, err := assembleRealm(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	owned.add(assembled.resources.close)
	return standalone(assembled, owned, log, cfg.Server), nil
}

func standalone(assembled *realm, owned *resources, log *zap.Logger, cfg httpserver.Config) *App {
	return &App{
		Access: assembled.Access, Provisioning: assembled.Provisioning, TemporaryPasswords: assembled.TemporaryPasswords,
		resources: owned,
		serve: func(ctx context.Context) error {
			return assembled.run(ctx, log, func(ctx context.Context) error {
				return httpserver.Run(ctx, log, cfg, assembled.handler)
			})
		},
	}
}

type realm struct {
	Access             *accessapp.App
	Provisioning       *accountservice.ProvisionService
	TemporaryPasswords *passwordservice.TemporaryPasswordService
	handler            http.Handler
	retention          retentionWorker
	workers            []deliveryWorker
	resources          *resources
}

func (r *resources) open(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, *redis.Client, *zap.Logger, error) {
	log := logger.CreateLogger(cfg.Logger)
	r.add(func() {
		if err := log.Sync(); err != nil {
			return // stdout/stderr may not support fsync; no buffered logger remains.
		}
	})
	r.add(zap.RedirectStdLog(log))

	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create postgres pool: %w", err)
	}
	r.add(pool.Close)
	log.Info("postgres pool created successfully")

	rdb, err := redisclient.New(ctx, cfg.Redis)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init redis: %w", err)
	}
	r.add(func() {
		if err := rdb.Close(); err != nil {
			log.Error("failed to close Redis")
		}
	})
	log.Info("redis created successfully")
	return pool, rdb, log, nil
}

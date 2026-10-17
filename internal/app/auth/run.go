package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	httpserver "github.com/Inforberi/financial-intelligence/internal/server/http"
)

type App struct {
	Access             *accessapp.App
	Provisioning       *accountservice.ProvisionService
	TemporaryPasswords *passwordservice.TemporaryPasswordService
	serve              func(context.Context) error
	resources          *resources
}

func (a *App) Run(ctx context.Context) error {
	defer a.Close()
	return a.serve(ctx)
}

// Close is idempotent. Normally Run closes the application; callers that do not
// start it must call Close themselves. Do not close it while Run is active.
func (a *App) Close() {
	a.resources.close()
}

type resources struct {
	once    sync.Once
	closers []func()
}

func (r *resources) add(close func()) {
	if close != nil {
		r.closers = append(r.closers, close)
	}
}

func (r *resources) close() {
	r.once.Do(func() {
		for i := len(r.closers) - 1; i >= 0; i-- {
			r.closers[i]()
		}
	})
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

type deliveryWorker interface {
	RunDelivery(context.Context, func(error))
}

func startDelivery(ctx context.Context, service deliveryWorker, log *zap.Logger,
) func() {
	return startBackground(ctx, func(ctx context.Context) {
		service.RunDelivery(ctx, func(err error) {
			if errors.Is(err, mfadomain.ErrRecoveryDelivery) {
				log.Error("MFA security notification delivery failed; inspect durable queue")
				return
			}
			log.Warn("email delivery processing failed")
		})
	})
}

func startBackground(ctx context.Context, run func(context.Context)) func() {
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(workerCtx)
	}()
	return func() { cancel(); <-done }
}

func runWithDelivery(ctx context.Context, log *zap.Logger, serve func(context.Context) error, workers ...deliveryWorker,
) error {
	for _, worker := range workers {
		stop := startDelivery(ctx, worker, log)
		defer stop()
	}
	return serve(ctx)
}

func serveAuth(log *zap.Logger, cfg httpserver.Config, handler http.Handler, retention *accountservice.RetentionService, workers ...deliveryWorker) func(context.Context) error {
	active := make([]deliveryWorker, 0, len(workers))
	for _, worker := range workers {
		if worker != nil {
			active = append(active, worker)
		}
	}
	return func(ctx context.Context) error {
		stopRetention := startBackground(ctx, func(ctx context.Context) {
			retention.RunRetention(ctx, func(error) { log.Warn("retention processing failed") })
		})
		defer stopRetention()
		serve := func(ctx context.Context) error {
			return httpserver.Run(ctx, log, cfg, handler)
		}
		return runWithDelivery(ctx, log, serve, active...)
	}
}

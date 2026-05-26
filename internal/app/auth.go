package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/hasher"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/httpserver"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/postgres"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/sessiontoken"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/router"
	register_postgres "github.com/Inforberi/financial-intelligence/internal/featers/register/repo/postgres"
	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
	register_http "github.com/Inforberi/financial-intelligence/internal/featers/register/transport/http"
	session_postgres "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/postgres"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"

	"go.uber.org/zap"
)

func Run() error {
	// init context
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// init config
	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// init logger
	log := logger.CreateLogger(cfg.Logger)
	defer func() {
		_ = log.Sync()
	}()
	undo := zap.RedirectStdLog(log)
	defer undo()

	// init postgres
	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	log.Info("postgres pool created successfully")

	// init redis
	rdb, err := redis.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("init redis: %w", err)
	}
	defer rdb.Close()
	log.Info("redis created successfully")

	// init argon tokenGen
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	now := clock.UTCClock{}
	tokenGen := sessiontoken.TokenManager{}

	// init session
	sessionRepo := session_postgres.New(pool)
	sessionService := session_service.New(now, sessionRepo, tokenGen, cfg.Session)

	// init register feater
	registerRepo := register_postgres.New(pool)
	registerService := register_service.New(argonHash, registerRepo, sessionService)
	registerLogger := log.With(zap.String("feature", "register"), zap.String("layer", "transport"))
	registerHandler := register_http.New(registerService, registerLogger)

	// init router
	r := router.New(router.Handlers{
		Register: registerHandler,
	})

	return httpserver.Run(ctx, log, cfg.Server, r)
}

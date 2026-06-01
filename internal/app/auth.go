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
	redis_client "github.com/Inforberi/financial-intelligence/internal/core/infra/redis"

	"github.com/Inforberi/financial-intelligence/internal/core/infra/sessiontoken"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/router"
	postgres_password "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/repo/postgres"
	password_service "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/service"
	password_http "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/transport/http"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"

	"go.uber.org/zap"
)

func Run() error {
	ctx := context.Background()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.New()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	log := logger.CreateLogger(cfg.Logger)
	defer func() {
		_ = log.Sync()
	}()
	undo := zap.RedirectStdLog(log)
	defer undo()

	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	log.Info("postgres pool created successfully")

	rdb, err := redis_client.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("init redis: %w", err)
	}
	defer rdb.Close()
	log.Info("redis created successfully")

	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	now := clock.UTCClock{}
	tokenGen := sessiontoken.TokenManager{}

	sessionRepo := session_redis.New(rdb)
	sessionService := session_service.New(now, sessionRepo, tokenGen, cfg.Session)

	passwordRepo := postgres_password.New(pool)
	passwordSvc := password_service.New(passwordRepo, sessionService, argonHash, now)
	passwordLogger := log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport"))
	passwordHandler := password_http.New(passwordSvc, passwordLogger)

	r := router.New(router.Handlers{
		Password: passwordHandler,
	})

	return httpserver.Run(ctx, log, cfg.Server, r)
}

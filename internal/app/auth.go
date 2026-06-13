package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	core_middleware "github.com/Inforberi/financial-intelligence/internal/core/transport/http/middleware"

	"github.com/Inforberi/financial-intelligence/internal/core/config"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/hasher"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/httpserver"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/postgres"
	redis_client "github.com/Inforberi/financial-intelligence/internal/core/infra/redis"

	"github.com/Inforberi/financial-intelligence/internal/core/infra/sessiontoken"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/core/transport/http/router"
	postgres_password "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/repo/postgres"
	password_service "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/service"
	password_http "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/transport/http"
	session_redis "github.com/Inforberi/financial-intelligence/internal/featers/session/repo/redis"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"

	"go.uber.org/zap"
)

func Run() error {
	// context
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

	// init pg
	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	log.Info("postgres pool created successfully")

	// init redis
	rdb, err := redis_client.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("init redis: %w", err)
	}
	defer rdb.Close()
	log.Info("redis created successfully")

	// init password hasher
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	// init clock
	now := clock.UTCClock{}
	// init token
	tokenGen := sessiontoken.TokenManager{}

	// init mailer
	mail := mailer.New(cfg.MailSender)

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}

	// init session feater
	sessionRepo := session_redis.New(rdb)
	sessionService := session_service.New(now, sessionRepo, tokenGen, cfg.Session)

	// init password feater
	passwordRepo := postgres_password.New(pool)
	passwordSvc := password_service.New(passwordRepo, sessionService, argonHash, now)
	passwordLogger := log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport"))
	passwordHandler := password_http.New(passwordSvc, passwordLogger)

	// init middleware
	mv := core_middleware.New(sessionService, log)

	r := router.New(router.Handlers{
		PasswordHandler: passwordHandler,
		Middleware:      mv,
		MailTest:        mailTest,
	})

	return httpserver.Run(ctx, log, cfg.Server, r)
}

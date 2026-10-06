package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/app/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/httpserver"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/modules/auth/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/transport/http"
	sessionredis "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/repository/redis"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/service"
	middleware "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
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
		if err := log.Sync(); err != nil {
			return
		} // stdout/stderr may not support fsync; no further buffered logger remains.
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
	rdb, err := redisclient.New(ctx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("init redis: %w", err)
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			log.Error("failed to close Redis")
		}
	}()
	log.Info("redis created successfully")

	// init password hasher
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)

	// init clock
	now := clock.UTCClock{}
	// init token
	tokenGen := tokengenerate.New()

	// init mailer
	mail := mailer.New(cfg.MailSender)

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}

	// init session feature
	sessionRepo := sessionredis.New(rdb)
	sessionService := sessionservice.New(now, sessionRepo, tokenGen, cfg.Session)

	// init password feature
	passwordRepo := passwordpostgres.New(pool)
	passwordRedisRepo := passwordredis.New(rdb)
	passwordSvc := passwordservice.New(
		passwordRepo,
		sessionService,
		argonHash,
		now,
		tokenGen,
		passwordRedisRepo,
		cfg.Password,
		mail,
	)
	passwordLogger := log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport"))
	passwordHandler := passwordhttp.New(passwordSvc, passwordLogger)

	// init middleware
	mv := middleware.New(sessionService, log)

	r := router.New(router.Handlers{
		PasswordHandler: passwordHandler,
		Middleware:      mv,
		MailTest:        mailTest,
		Config:          cfg,
		Logger:          log,
		ReadyCheck: func(ctx context.Context) error {
			if err := pool.Ping(ctx); err != nil {
				return err
			}
			return rdb.Ping(ctx).Err()
		},
	})

	return httpserver.Run(ctx, log, cfg.Server, r)
}

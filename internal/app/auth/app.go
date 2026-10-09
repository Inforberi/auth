package auth

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/logger"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
	redisclient "github.com/Inforberi/financial-intelligence/internal/infra/redis"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	httpserver "github.com/Inforberi/financial-intelligence/internal/server/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func New(ctx context.Context, cfg *config.Config) (_ *App, err error) {
	resources := &resources{}
	defer func() {
		if err != nil {
			resources.close()
		}
	}()
	log := logger.CreateLogger(cfg.Logger)
	resources.add(func() {
		if err := log.Sync(); err != nil {
			return // stdout/stderr may not support fsync; no buffered logger remains.
		}
	})
	resources.add(zap.RedirectStdLog(log))

	pool, err := postgres.New(ctx, cfg.Postgres)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	resources.add(pool.Close)
	log.Info("postgres pool created successfully")

	rdb, err := redisclient.New(ctx, cfg.Redis)
	if err != nil {
		return nil, fmt.Errorf("init redis: %w", err)
	}
	resources.add(func() {
		if err := rdb.Close(); err != nil {
			log.Error("failed to close Redis")
		}
	})
	log.Info("redis created successfully")

	now := clock.UTCClock{}
	tokenGen := tokengenerate.New()
	mail := mailer.New(cfg.MailSender)
	accountSvc, passwordRepo, err := assembleAccount(pool, rdb, mail, cfg.Account)
	if err != nil {
		return nil, fmt.Errorf("assemble account: %w", err)
	}
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)
	sessionSvc := sessionservice.New(now, sessionpostgres.New(pool), tokenGen, cfg.Session)
	passwordSvc := passwordservice.New(passwordRepo, sessionSvc, argonHash)
	resetCipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	recoverySvc := passwordservice.NewRecovery(passwordRepo, resetCipher, passwordredis.New(rdb), mail, argonHash, cfg.Password)
	passwordHandler := passwordhttp.New(passwordSvc,
		log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport")))
	middleware := sessionhttp.New(sessionSvc, log)

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}
	handler := router.New(router.Handlers{
		Recovery:        passwordhttp.NewRecovery(recoverySvc, log),
		Account:         accounthttp.New(accountSvc, log),
		PasswordHandler: passwordHandler,
		Middleware:      middleware,
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
	return &App{
		resources: resources,
		serve: func(ctx context.Context) error {
			stopRecovery := startDelivery(ctx, recoverySvc, log)
			defer stopRecovery()
			stop := startDelivery(ctx, accountSvc, log)
			defer stop()
			return httpserver.Run(ctx, log, cfg.Server, handler)
		},
	}, nil
}

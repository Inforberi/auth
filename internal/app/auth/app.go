package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
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
	pool, rdb, log, err := resources.open(ctx, cfg)
	if err != nil {
		return nil, err
	}

	now := clock.UTCClock{}
	tokenGen := tokengenerate.New()
	mail := mailer.New(cfg.MailSender)
	accountSvc, accountRepo, err := assembleAccount(pool, rdb, mail, cfg.Account, cfg.EmailChange.Enabled)
	if err != nil {
		return nil, fmt.Errorf("assemble account: %w", err)
	}
	passwordRepo := assembleRegistration(pool, accountSvc, accountRepo)
	argonHash := hasher.NewArgon2idHash(1, 32, 64*1024, 32, 256)
	sessionRepo := sessionpostgres.New(pool)
	sessionSvc := sessionservice.New(now, sessionRepo, tokenGen, cfg.Session)
	passwordSvc := passwordservice.New(passwordRepo, sessionSvc, argonHash)
	resetCipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	recoverySvc := passwordservice.NewRecovery(passwordRepo, resetCipher, passwordredis.New(rdb), mail, argonHash, cfg.Password)
	passwordHandler := passwordhttp.New(passwordSvc,
		log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport")))
	middleware := sessionhttp.New(sessionSvc, log)
	var emailChange *accounthttp.EmailChangeHandler
	if cfg.EmailChange.Enabled {
		changeSvc := accountservice.NewEmailChange(accountRepo, argonHash, accountSvc, cfg.EmailChange)
		emailChange = accounthttp.NewEmailChange(changeSvc, log)
	}

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}
	handler := router.New(router.Handlers{
		Session:         sessionhttp.NewHandler(sessionservice.NewManagement(sessionRepo), log),
		Recovery:        passwordhttp.NewRecovery(recoverySvc, log),
		Account:         accounthttp.New(accountSvc, log),
		EmailChange:     emailChange,
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
			return runWithDelivery(ctx, log, func(ctx context.Context) error {
				return httpserver.Run(ctx, log, cfg.Server, handler)
			}, recoverySvc, accountSvc)
		},
	}, nil
}

func assembleRegistration(pool *pgxpool.Pool, service *accountservice.Service, repo *accountpostgres.Repository) *passwordpostgres.PasswordRepo {
	return passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := service.Prepare(email)
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
}

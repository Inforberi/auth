package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessapp "github.com/Inforberi/financial-intelligence/internal/app/access"
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
	access, err := accessapp.New(ctx, pool, cfg.Access)
	if err != nil {
		return nil, fmt.Errorf("assemble access: %w", err)
	}

	now := clock.UTCClock{}
	tokenGen := tokengenerate.New()
	mail := mailer.New(cfg.MailSender)
	accountSvc, accountRepo, err := assembleAccount(pool, rdb, mail, cfg.Account, accountpostgres.DeliveryConfig{EmailChanges: cfg.EmailChange.Enabled, Invitations: cfg.Invitation.Enabled, EmailBinding: cfg.EmailBinding.Enabled})
	if err != nil {
		return nil, fmt.Errorf("assemble account: %w", err)
	}
	passwordRepo := assembleRegistration(pool, accountSvc, accountRepo)
	emailBinding, err := assembleEmailBinding(accountRepo, rdb, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email binding: %w", err)
	}
	retentionSvc := accountservice.NewRetention(accountRepo, cfg.Retention)
	argonHash := hasher.NewBounded(hasher.NewArgon2idHash(3, 32, 64*1024, 4, 32), cfg.Capacity.HashConcurrency)
	setup, err := assembleSetup(accountRepo, rdb, mail, argonHash, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble setup: %w", err)
	}
	sessionRepo := sessionpostgres.New(pool)
	sessionSvc := sessionservice.New(now, sessionRepo, tokenGen, cfg.Session)
	loginSvc, mfaHandler, mfaDelivery, err := assembleMFA(ctx, pool, rdb, sessionSvc, tokenGen, mail, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble MFA: %w", err)
	}
	emailOTP, emailOTPDelivery, err := assembleEmailOTP(pool, rdb, mail, loginSvc, tokenGen, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email OTP: %w", err)
	}
	resetCipher, err := secretbox.NewScoped(cfg.Account.EncryptionKey, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	passwordLimits := passwordredis.New(rdb)
	loginLimit := passwordservice.NewLoginLimit(passwordLimits, resetCipher, cfg.Capacity)
	passwordSvc := passwordservice.New(passwordRepo, loginSvc, argonHash, loginLimit)
	recoverySvc := passwordservice.NewRecovery(passwordRepo, resetCipher, passwordLimits, mail, argonHash, cfg.Password)
	passwordHandler := passwordhttp.New(passwordSvc,
		log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport")))
	middleware := sessionhttp.New(sessionSvc, log)
	telegram, closeTelegram, err := assembleTelegram(ctx, cfg, accountRepo, rdb, loginSvc, log)
	if err != nil {
		return nil, fmt.Errorf("assemble telegram: %w", err)
	}
	if closeTelegram != nil {
		resources.add(closeTelegram)
	}
	google, closeGoogle, err := assembleGoogle(ctx, cfg, accountRepo, rdb, loginSvc, log)
	if err != nil {
		return nil, fmt.Errorf("assemble Google: %w", err)
	}
	if closeGoogle != nil {
		resources.add(closeGoogle)
	}
	var emailChange *accounthttp.EmailChangeHandler
	var protectedRecovery *passwordhttp.ProtectedRecoveryHandler
	var activation *passwordhttp.ActivationHandler
	var temporary *passwordservice.TemporaryPasswordService
	var temporaryHandler *passwordhttp.TemporaryPasswordHandler
	if cfg.TemporaryPassword.Enabled {
		temporaryRepo := passwordpostgres.NewTemporaryPassword(pool, accountRepo.ProvisionInTransaction)
		temporary = passwordservice.NewTemporaryPassword(temporaryRepo, argonHash, passwordLimits, resetCipher.Digest, loginLimit, cfg.TemporaryPassword)
		temporaryHandler = passwordhttp.NewTemporaryPassword(temporary, log)
	}
	var provisioning *accountservice.ProvisionService
	if cfg.Invitation.Enabled {
		provisioning = accountservice.NewProvisioning(accountRepo, accountSvc, cfg.Invitation)
		activation = passwordhttp.NewActivation(passwordservice.NewActivation(accountRepo, recoverySvc, cfg.Invitation), log)
	}
	if cfg.EmailChange.Enabled {
		changeSvc := accountservice.NewEmailChange(accountRepo, argonHash, accountSvc, cfg.EmailChange, cfg.Session.FreshAuthTTL)
		emailChange = accounthttp.NewEmailChange(changeSvc, log)
		protectedRecovery = passwordhttp.NewProtectedRecovery(passwordservice.NewProtectedRecovery(accountRepo, recoverySvc), log)
	}

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}
	handler := router.New(router.Handlers{
		Setup:             setup,
		EmailBinding:      emailBinding,
		MFA:               mfaHandler,
		Session:           sessionhttp.NewHandler(sessionservice.NewManagement(sessionRepo), log),
		Rotation:          sessionhttp.NewRotation(sessionservice.NewRotation(sessionRepo, tokenGen), log),
		Reauthentication:  passwordhttp.NewReauthentication(passwordservice.NewReauthentication(passwordRepo, sessionRepo, argonHash, loginLimit, tokenGen, cfg.Session.FreshAuthTTL), log),
		Recovery:          passwordhttp.NewRecovery(recoverySvc, log),
		Account:           accounthttp.New(accountSvc, log),
		EmailChange:       emailChange,
		ProtectedRecovery: protectedRecovery,
		Activation:        activation,
		TemporaryPassword: temporaryHandler,
		Telegram:          telegram,
		Google:            google,
		EmailOTP:          emailOTP,
		PasswordHandler:   passwordHandler,
		Middleware:        middleware,
		MailTest:          mailTest,
		Config:            cfg,
		Logger:            log,
		ReadyCheck: func(ctx context.Context) error {
			if err := pool.Ping(ctx); err != nil {
				return err
			}
			return rdb.Ping(ctx).Err()
		},
	})
	return &App{
		Access:             access,
		Provisioning:       provisioning,
		TemporaryPasswords: temporary,
		resources:          resources,
		serve: func(ctx context.Context) error {
			stopRetention := startBackground(ctx, func(ctx context.Context) {
				retentionSvc.RunRetention(ctx, func(error) { log.Warn("retention processing failed") })
			})
			defer stopRetention()
			serve := func(ctx context.Context) error {
				return httpserver.Run(ctx, log, cfg.Server, handler)
			}
			workers := []deliveryWorker{recoverySvc, accountSvc, mfaDelivery}
			if emailOTPDelivery != nil {
				workers = append(workers, emailOTPDelivery)
			}
			return runWithDelivery(ctx, log, serve, workers...)
		},
	}, nil
}

func assembleRegistration(pool *pgxpool.Pool, service *accountservice.Service, repo *accountpostgres.Repository) *passwordpostgres.PasswordRepo {
	return passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := service.PrepareVerification(email)
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
}

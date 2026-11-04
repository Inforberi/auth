package auth

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	accountapp "github.com/Inforberi/financial-intelligence/internal/app/auth/account"
	methodapp "github.com/Inforberi/financial-intelligence/internal/app/auth/methods"
	mfaapp "github.com/Inforberi/financial-intelligence/internal/app/auth/mfa"
	settingsapp "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	setupapp "github.com/Inforberi/financial-intelligence/internal/app/auth/setup"
	tokenapp "github.com/Inforberi/financial-intelligence/internal/app/auth/token"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	registrationapp "github.com/Inforberi/financial-intelligence/internal/auth/account/registration"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/transport/http"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/transport/http"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func Assemble(ctx context.Context, cfg *config.Config, deps Dependencies) (_ *Runtime, err error) {
	runtimeConfig := *cfg
	cfg = &runtimeConfig
	owned := &Resources{}
	defer func() {
		if err != nil {
			owned.Close()
		}
	}()
	if err := deps.Validate(); err != nil {
		return nil, err
	}
	pool, rdb, log, argonHash := deps.Pool, deps.Redis, deps.Logger, deps.Hash
	scope := deps.Scope
	access, policy, providers, err := settingsapp.AssemblePolicy(ctx, scope, pool, cfg)
	if err != nil {
		return nil, fmt.Errorf("assemble access and auth policy: %w", err)
	}
	now := clock.UTCClock{}
	tokenGen := tokengenerate.New()
	mail, smtpSettings, err := settingsapp.AssembleSMTP(ctx, scope, pool, rdb, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble SMTP settings: %w", err)
	}
	accountRepo := accountpostgres.NewWithDelivery(pool, accountpostgres.DeliveryConfig{EmailChanges: cfg.EmailChange.Enabled, Invitations: cfg.Invitation.Enabled, EmailBinding: cfg.EmailBinding.Enabled})
	accountRuntime, err := accountapp.Assemble(scope, accountRepo, rdb, mail, cfg.Account)
	if err != nil {
		return nil, fmt.Errorf("assemble account: %w", err)
	}
	accountSvc := accountRuntime.Verification
	passwordRepo := registrationapp.Assemble(pool, accountSvc, accountRepo)
	emailBinding, err := accountapp.AssembleEmailBinding(scope, accountRepo, rdb, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email binding: %w", err)
	}
	retentionSettings, err := settingsapp.AssembleRetention(ctx, pool, cfg.Retention)
	if err != nil {
		return nil, fmt.Errorf("assemble retention settings: %w", err)
	}
	retentionSvc := accountservice.NewRetention(accountRepo, cfg.Retention).WithSettings(retentionSettings)
	setup, err := setupapp.Assemble(scope, accountRepo, rdb, mail, argonHash, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble setup: %w", err)
	}
	sessionRepo := sessionpostgres.New(pool)
	sessionSvc := sessionservice.New(now, sessionRepo, tokenGen, cfg.Session)
	mfa, err := mfaapp.Assemble(ctx, scope, pool, rdb, sessionSvc, tokenGen, mail, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble MFA: %w", err)
	}
	loginSvc := mfa.Sessions
	emailOTP, err := methodapp.AssembleEmailOTP(scope, pool, rdb, mail, loginSvc, tokenGen, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email OTP: %w", err)
	}
	password, err := methodapp.AssemblePassword(scope, passwordRepo, rdb, loginSvc, argonHash, policy, mail, cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := tokenapp.Assemble(ctx, scope, pool, rdb, cfg, tokenapp.NativeLoginDependencies{Password: password.Service, MFA: mfa, Email: emailOTP}, access.Catalog(), cfg.Account.EncryptionKey, owned, log)
	if err != nil {
		return nil, fmt.Errorf("assemble JWT: %w", err)
	}
	passwordHandler := passwordhttp.New(password.Service,
		log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport")))
	middleware := sessionhttp.New(sessionSvc, log)
	telegram, closeTelegram, err := methodapp.AssembleTelegram(ctx, scope, cfg, accountRepo, rdb, loginSvc, policy, providers, log)
	if err != nil {
		return nil, fmt.Errorf("assemble telegram: %w", err)
	}
	owned.Add(closeTelegram)
	google, closeGoogle, err := methodapp.AssembleGoogle(ctx, scope, cfg, accountRepo, rdb, loginSvc, policy, providers, log)
	if err != nil {
		return nil, fmt.Errorf("assemble Google: %w", err)
	}
	owned.Add(closeGoogle)
	temporary := password.AssembleTemporary(pool, accountRepo, argonHash, cfg, log)
	management := accountRuntime.AssembleManagement(argonHash, password.Recovery, cfg, log)
	activation := password.AssembleActivation(accountRepo, argonHash, cfg, log)

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}
	handler := router.New(router.Handlers{
		Tokens:            tokens.Handler,
		NativeTokens:      tokens.Native,
		Introspection:     tokens.Introspection,
		UserDirectory:     accounthttp.NewUserDirectory(accountservice.NewUserDirectory(accountRepo), log),
		UserLifecycle:     accounthttp.NewUserLifecycle(accountservice.NewUserLifecycle(accountRepo), log),
		Provisioning:      management.ProvisioningHandler,
		TemporaryAdmin:    temporary.Admin,
		Access:            accesshttp.New(access.Service, log),
		AuthSettings:      settingshttp.NewWithTokenDeployment(policy, cfg.AvailableAuthMethods(), tokens.Deployment, log),
		SMTPSettings:      smtpSettings,
		ProviderSettings:  settingsprovidershttp.NewProviders(providers, log),
		RetentionSettings: settingsretentionhttp.NewRetention(retentionSettings, log),
		MFASettings:       settingshttp.NewMFA(settingsservice.NewMFA(settingspostgres.New(pool), cfg.MFA.Enabled), log),
		Setup:             setup,
		EmailBinding:      emailBinding,
		MFA:               mfa.Handler, MFALogin: mfa.LoginHandler, MFARecovery: mfa.RecoveryHandler,
		Session:           sessionhttp.NewHandler(sessionservice.NewManagement(sessionRepo), log),
		Activity:          sessionhttp.NewActivity(sessionservice.NewActivity(sessionRepo), log),
		Rotation:          sessionhttp.NewRotation(sessionservice.NewRotation(sessionRepo, tokenGen), log),
		Reauthentication:  password.Reauthentication(passwordRepo, sessionRepo, argonHash, tokenGen, cfg.Session.FreshAuthTTL, log),
		Recovery:          passwordrecoveryhttp.NewRecovery(password.Recovery, log),
		Account:           accountemailhttp.New(accountSvc, log),
		EmailChange:       management.EmailChange,
		ProtectedRecovery: management.ProtectedRecovery,
		Activation:        activation,
		TemporaryPassword: temporary.Handler,
		Telegram:          telegram,
		Google:            google,
		EmailOTP:          emailOTP.Handler,
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
	return &Runtime{
		Access:             access,
		Provisioning:       management.Provisioning,
		TemporaryPasswords: temporary.Service,
		resources:          owned,
		Handler:            handler,
		retention:          retentionSvc,
		workers:            DeliveryWorkers(password.Recovery, accountSvc, mfa.Delivery, emailOTP.Delivery),
	}, nil
}

package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountemailhttp "github.com/Inforberi/financial-intelligence/internal/auth/account/email/transport/http"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	accountprovisioninghttp "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/transport/http"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	passwordprovisioninghttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/transport/http"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	passwordrecoveryhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/dev"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func assembleRealm(ctx context.Context, cfg *config.Config, deps realmDependencies) (_ *realm, err error) {
	runtimeConfig := *cfg
	cfg = &runtimeConfig
	owned := &resources{}
	defer func() {
		if err != nil {
			owned.close()
		}
	}()
	if err := deps.validate(); err != nil {
		return nil, err
	}
	pool, rdb, log, argonHash := deps.pool, deps.redis, deps.log, deps.hash
	security := realmSecurity{scope: deps.scope}
	access, policy, providers, err := security.assembleAccessPolicy(ctx, pool, cfg)
	if err != nil {
		return nil, fmt.Errorf("assemble access and auth policy: %w", err)
	}
	now := clock.UTCClock{}
	tokenGen := tokengenerate.New()
	mail, smtpSettings, err := security.assembleSMTP(ctx, pool, rdb, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble SMTP settings: %w", err)
	}
	accountRuntime, err := security.assembleAccount(pool, rdb, mail, cfg.Account, accountpostgres.DeliveryConfig{EmailChanges: cfg.EmailChange.Enabled, Invitations: cfg.Invitation.Enabled, EmailBinding: cfg.EmailBinding.Enabled})
	if err != nil {
		return nil, fmt.Errorf("assemble account: %w", err)
	}
	accountSvc, accountRepo := accountRuntime.verification, accountRuntime.repository
	passwordRepo := assembleRegistration(pool, accountSvc, accountRepo)
	emailBinding, err := security.assembleEmailBinding(accountRepo, rdb, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email binding: %w", err)
	}
	retentionSettings, err := assembleRetentionSettings(ctx, pool, cfg.Retention)
	if err != nil {
		return nil, fmt.Errorf("assemble retention settings: %w", err)
	}
	retentionSvc := accountservice.NewRetention(accountRepo, cfg.Retention).WithSettings(retentionSettings)
	setup, err := security.assembleSetup(accountRepo, rdb, mail, argonHash, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble setup: %w", err)
	}
	sessionRepo := sessionpostgres.New(pool)
	sessionSvc := sessionservice.New(now, sessionRepo, tokenGen, cfg.Session)
	mfa, err := security.assembleMFA(ctx, pool, rdb, sessionSvc, tokenGen, mail, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble MFA: %w", err)
	}
	loginSvc := mfa.sessions
	emailOTP, err := security.assembleEmailOTP(pool, rdb, mail, loginSvc, tokenGen, cfg, log)
	if err != nil {
		return nil, fmt.Errorf("assemble email OTP: %w", err)
	}
	password, err := security.assemblePassword(passwordRepo, rdb, loginSvc, argonHash, policy, mail, cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := security.assembleTokens(ctx, pool, rdb, cfg, nativeLoginDependencies{password: password.service, mfa: mfa, email: emailOTP}, access.Catalog(), cfg.Account.EncryptionKey, owned, log)
	if err != nil {
		return nil, fmt.Errorf("assemble JWT: %w", err)
	}
	passwordHandler := passwordhttp.New(password.service,
		log.With(zap.String("feature", "password_auth"), zap.String("layer", "transport")))
	middleware := sessionhttp.New(sessionSvc, log)
	telegram, closeTelegram, err := security.assembleTelegram(ctx, cfg, accountRepo, rdb, loginSvc, policy, providers, log)
	if err != nil {
		return nil, fmt.Errorf("assemble telegram: %w", err)
	}
	owned.add(closeTelegram)
	google, closeGoogle, err := security.assembleGoogle(ctx, cfg, accountRepo, rdb, loginSvc, policy, providers, log)
	if err != nil {
		return nil, fmt.Errorf("assemble Google: %w", err)
	}
	owned.add(closeGoogle)
	var emailChange *accountemailhttp.EmailChangeHandler
	var protectedRecovery *passwordrecoveryhttp.ProtectedRecoveryHandler
	var activation *passwordprovisioninghttp.ActivationHandler
	var temporary *passwordprovisioning.TemporaryPasswordService
	var temporaryHandler *passwordprovisioninghttp.TemporaryPasswordHandler
	var temporaryAdmin *passwordprovisioninghttp.TemporaryAdminHandler
	if cfg.TemporaryPassword.Enabled {
		temporaryRepo := passwordpostgres.NewTemporaryPassword(pool, accountRepo.ProvisionInTransaction)
		temporary = passwordprovisioning.NewTemporaryPassword(temporaryRepo, argonHash, password.limits, password.cipher.Digest, password.loginLimit, cfg.TemporaryPassword)
		temporaryHandler = passwordprovisioninghttp.NewTemporaryPassword(temporary, log)
		temporaryAdmin = passwordprovisioninghttp.NewTemporaryAdmin(temporary, log)
	}
	var provisioning *accountprovisioning.ProvisionService
	var provisioningHandler *accountprovisioninghttp.ProvisioningHandler
	if cfg.Invitation.Enabled {
		provisioning = accountprovisioning.NewProvisioning(accountRepo, accountRuntime.limits, accountRuntime.cipher, cfg.Invitation)
		provisioningHandler = accountprovisioninghttp.NewProvisioning(provisioning, log)
		activation = passwordprovisioninghttp.NewActivation(passwordprovisioning.NewActivation(accountRepo, argonHash, password.limits, password.cipher.Digest, cfg.Invitation), log)
	}
	if cfg.EmailChange.Enabled {
		changeSvc := accountemail.NewEmailChange(accountRepo, argonHash, accountRuntime.limits, accountRuntime.cipher, cfg.EmailChange, cfg.Session.FreshAuthTTL)
		emailChange = accountemailhttp.NewEmailChange(changeSvc, log)
		protectedRecovery = passwordrecoveryhttp.NewProtectedRecovery(passwordrecovery.NewProtectedRecovery(accountRepo, password.recovery), log)
	}

	var mailTest *dev.MailTestHandler
	if cfg.Logger.Env == "dev" {
		mailTest = dev.NewMailTest(mail, log)
	}
	handler := router.New(router.Handlers{
		Tokens:            tokens.handler,
		NativeTokens:      tokens.native,
		Introspection:     tokens.introspection,
		UserDirectory:     accounthttp.NewUserDirectory(accountservice.NewUserDirectory(accountRepo), log),
		UserLifecycle:     accounthttp.NewUserLifecycle(accountservice.NewUserLifecycle(accountRepo), log),
		Provisioning:      provisioningHandler,
		TemporaryAdmin:    temporaryAdmin,
		Access:            accesshttp.New(access.Service, log),
		AuthSettings:      settingshttp.NewWithTokenDeployment(policy, cfg.AvailableAuthMethods(), tokens.deployment, log),
		SMTPSettings:      smtpSettings,
		ProviderSettings:  settingshttp.NewProviders(providers, log),
		RetentionSettings: settingshttp.NewRetention(retentionSettings, log),
		MFASettings:       settingshttp.NewMFA(settingsservice.NewMFA(settingspostgres.New(pool), cfg.MFA.Enabled), log),
		Setup:             setup,
		EmailBinding:      emailBinding,
		MFA:               mfa.handler, MFALogin: mfa.loginHandler, MFARecovery: mfa.recoveryHandler,
		Session:           sessionhttp.NewHandler(sessionservice.NewManagement(sessionRepo), log),
		Activity:          sessionhttp.NewActivity(sessionservice.NewActivity(sessionRepo), log),
		Rotation:          sessionhttp.NewRotation(sessionservice.NewRotation(sessionRepo, tokenGen), log),
		Reauthentication:  passwordhttp.NewReauthentication(passwordservice.NewReauthentication(passwordRepo, sessionRepo, argonHash, password.loginLimit, tokenGen, cfg.Session.FreshAuthTTL), log),
		Recovery:          passwordrecoveryhttp.NewRecovery(password.recovery, log),
		Account:           accountemailhttp.New(accountSvc, log),
		EmailChange:       emailChange,
		ProtectedRecovery: protectedRecovery,
		Activation:        activation,
		TemporaryPassword: temporaryHandler,
		Telegram:          telegram,
		Google:            google,
		EmailOTP:          emailOTP.handler,
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
	return &realm{
		Access:             access,
		Provisioning:       provisioning,
		TemporaryPasswords: temporary,
		resources:          owned,
		handler:            handler,
		retention:          retentionSvc,
		workers:            realmDeliveryWorkers(password.recovery, accountSvc, mfa.delivery, emailOTP.delivery),
	}, nil
}

func assembleRegistration(pool *pgxpool.Pool, service *accountemail.Verification, repo *accountpostgres.Repository) *passwordpostgres.PasswordRepo {
	return passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		prepared, err := service.PrepareVerification(email)
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
}

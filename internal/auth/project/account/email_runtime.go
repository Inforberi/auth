package account

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordrecovery "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type ProjectEmailRuntime struct {
	otpCipher          *secretbox.Cipher
	mfaCipher          *secretbox.Cipher
	smtp               *projectbinding.SMTP
	verificationCipher accountservice.Cipher
	verificationLimits accountservice.Limiter
	resetCipher        passwordservice.RecoveryCipher
	resetLimits        passwordservice.RecoveryLimiter
}

func NewProjectEmailRuntime(key projectruntime.Key, root string, allowed []string, deps projectbinding.ProjectSMTPDependencies) (*ProjectEmailRuntime, error) {
	smtp, err := projectbinding.NewSMTP(key, root, allowed, deps)
	if err != nil {
		return nil, err
	}
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}

	verificationCipher, err := secretbox.ForScope(scope, root, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	resetCipher, err := secretbox.ForScope(scope, root, "password-reset:v1")
	if err != nil {
		return nil, err
	}
	verificationLimits, err := accountredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	resetLimits, err := passwordredis.NewScoped(deps.Redis, scope)
	if err != nil {
		return nil, err
	}
	otpCipher, err := secretbox.ForScope(scope, root, "email-login:v1")
	if err != nil {
		return nil, err
	}
	mfaCipher, err := secretbox.ForScope(scope, root, "mfa:v1")
	if err != nil {
		return nil, err
	}
	return &ProjectEmailRuntime{smtp: smtp, otpCipher: otpCipher, mfaCipher: mfaCipher, verificationCipher: verificationCipher, verificationLimits: verificationLimits, resetCipher: resetCipher, resetLimits: resetLimits}, nil
}

func (p *ProjectEmailRuntime) use(ctx context.Context, operation func(context.Context, *pgxpool.Pool, *mailer.Mailer) error) error {
	return p.smtp.Use(ctx, operation)
}

func (p *ProjectEmailRuntime) verification(pool *pgxpool.Pool, mail *mailer.Mailer, cfg accountservice.Config) *accountemail.Verification {
	return accountemail.NewVerification(accountpostgres.New(pool), p.verificationLimits, p.verificationCipher, mail, cfg)
}

func (p *ProjectEmailRuntime) recovery(pool *pgxpool.Pool, mail *mailer.Mailer, hash *hasher.Bounded, cfg passwordrecovery.Config) *passwordrecovery.RecoveryService {
	return passwordrecovery.NewRecovery(passwordpostgres.New(pool), p.resetCipher, p.resetLimits, mail, hash, cfg)
}

func (p *ProjectEmailRuntime) deliver(ctx context.Context, verification bool) error {
	return p.DeliverAccount(ctx, verification, accountpostgres.DeliveryConfig{})
}

func (p *ProjectEmailRuntime) DeliverAccount(ctx context.Context, verification bool, cfg accountpostgres.DeliveryConfig) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		if verification {
			worker := accountemail.NewVerification(accountpostgres.NewWithDelivery(pool, cfg), p.verificationLimits, p.verificationCipher, mail, accountservice.Config{})
			return worker.DeliverOne(ctx)
		}
		// Delivery consumes an existing encrypted body; it never hashes or builds a reset URL.
		_, err := p.recovery(pool, mail, nil, passwordrecovery.Config{}).DeliverOne(ctx)
		return err
	})
}

func (p *ProjectEmailRuntime) DeliverEmailOTP(ctx context.Context) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		_, err := otpservice.NewDelivery(otppostgres.New(pool), p.otpCipher, mail).DeliverOne(ctx)
		return err
	})
}

func (p *ProjectEmailRuntime) DeliverMFARecovery(ctx context.Context) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		worker, err := mfadelivery.NewSecurityDelivery(mfapostgres.New(pool), p.mfaCipher, mail)
		if err != nil {
			return err
		}
		_, err = worker.DeliverOne(ctx)
		return err
	})
}

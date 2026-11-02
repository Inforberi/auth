package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountredis "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/redis"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	otppostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/repository/postgres"
	otpservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordredis "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/redis"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type projectEmailRuntime struct {
	otpCipher          *secretbox.Cipher
	mfaCipher          *secretbox.Cipher
	smtp               *projectSMTP
	verificationCipher accountservice.Cipher
	verificationLimits accountservice.Limiter
	resetCipher        passwordservice.RecoveryCipher
	resetLimits        passwordservice.RecoveryLimiter
}

func newProjectEmailRuntime(key projectruntime.Key, root string, allowed []string, deps ProjectSMTPDependencies) (*projectEmailRuntime, error) {
	smtp, err := newProjectSMTP(key, root, allowed, deps)
	if err != nil {
		return nil, err
	}
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	if err != nil {
		return nil, err
	}
	security := realmSecurity{scope: scope}
	verificationCipher, err := security.cipher(root, "email-verification:v1")
	if err != nil {
		return nil, err
	}
	resetCipher, err := security.cipher(root, "password-reset:v1")
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
	otpCipher, err := security.cipher(root, "email-login:v1")
	if err != nil {
		return nil, err
	}
	mfaCipher, err := security.cipher(root, "mfa:v1")
	if err != nil {
		return nil, err
	}
	return &projectEmailRuntime{smtp: smtp, otpCipher: otpCipher, mfaCipher: mfaCipher, verificationCipher: verificationCipher, verificationLimits: verificationLimits, resetCipher: resetCipher, resetLimits: resetLimits}, nil
}

func (p *projectEmailRuntime) use(ctx context.Context, operation func(context.Context, *pgxpool.Pool, *mailer.Mailer) error) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return p.smtp.registry.UsePool(ctx, p.smtp.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		if err := p.smtp.requireCurrent(ctx); err != nil {
			return err
		}
		// The source uses this lease, not another registry acquisition. No service escapes it.
		mail := mailer.NewWithSource(func(ctx context.Context) (mailer.Config, error) { return p.smtp.credentialsInPool(ctx, pool) })
		if err := operation(ctx, pool, mail); err != nil {
			return err
		}
		return p.smtp.requireCurrent(ctx)
	})
}

func (p *projectEmailRuntime) verification(pool *pgxpool.Pool, mail *mailer.Mailer, cfg accountservice.Config) *accountservice.Service {
	return accountservice.New(accountpostgres.New(pool), p.verificationLimits, p.verificationCipher, mail, cfg)
}

func (p *projectEmailRuntime) recovery(pool *pgxpool.Pool, mail *mailer.Mailer, hash *hasher.Bounded, cfg passwordservice.Config) *passwordservice.RecoveryService {
	return passwordservice.NewRecovery(passwordpostgres.New(pool), p.resetCipher, p.resetLimits, mail, hash, cfg)
}

func (p *projectEmailRuntime) deliver(ctx context.Context, verification bool) error {
	return p.deliverAccount(ctx, verification, accountpostgres.DeliveryConfig{})
}

func (p *projectEmailRuntime) deliverAccount(ctx context.Context, verification bool, cfg accountpostgres.DeliveryConfig) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		if verification {
			worker := accountservice.New(accountpostgres.NewWithDelivery(pool, cfg), p.verificationLimits, p.verificationCipher, mail, accountservice.Config{})
			return worker.DeliverOne(ctx)
		}
		// Delivery consumes an existing encrypted body; it never hashes or builds a reset URL.
		_, err := p.recovery(pool, mail, nil, passwordservice.Config{}).DeliverOne(ctx)
		return err
	})
}

func (p *projectEmailRuntime) deliverEmailOTP(ctx context.Context) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		_, err := otpservice.NewDelivery(otppostgres.New(pool), p.otpCipher, mail).DeliverOne(ctx)
		return err
	})
}

func (p *projectEmailRuntime) deliverMFARecovery(ctx context.Context) error {
	return p.use(ctx, func(ctx context.Context, pool *pgxpool.Pool, mail *mailer.Mailer) error {
		worker, err := mfaservice.NewSecurityDelivery(mfapostgres.New(pool), p.mfaCipher, mail)
		if err != nil {
			return err
		}
		_, err = worker.DeliverOne(ctx)
		return err
	})
}

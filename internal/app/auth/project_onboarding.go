package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type ProjectOnboardingConfig struct {
	Project            projectdomain.Project
	Keys               credentials.OnboardingKeys
	SMTPAllowedTargets []string
	HTTP               requestmiddleware.CapacityConfig
	Proxy              requestmiddleware.ProxyConfig
}

// Dependencies are borrowed; constructing or rejecting a runtime never closes them.
type ProjectOnboardingDependencies struct {
	Pool   *pgxpool.Pool
	Redis  *redis.Client
	Logger *zap.Logger
	Hash   *hasher.Bounded
	// Admit must check current onboarding authority for the exact reservation/binding.
	// CheckCurrent alone, a receipt or a cached Project snapshot is not sufficient.
	Admit func(context.Context) (bool, error)
}

func NewProjectOnboarding(ctx context.Context, cfg ProjectOnboardingConfig, deps ProjectOnboardingDependencies) (http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if deps.Admit == nil {
		return nil, errors.New("project onboarding requires current admission")
	}
	p := cfg.Project
	scope, err := realmscope.New("project", string(p.ID))
	if err != nil {
		return nil, err
	}
	borrowed := realmDependencies{pool: deps.Pool, redis: deps.Redis, log: deps.Logger, hash: deps.Hash, scope: scope}
	if err := borrowed.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	admit := func(check context.Context) error {
		allowed, err := deps.Admit(check)
		if err != nil || !allowed || check.Err() != nil {
			return errors.New("project onboarding unavailable")
		}
		return nil
	}
	if err := admit(ctx); err != nil {
		return nil, err
	}
	if err := projectpostgres.CheckOnboardingRuntime(ctx, deps.Pool, cfg.Keys.Proof()); err != nil {
		return nil, err
	}
	security := realmSecurity{scope: scope}
	mail, err := security.projectOnboardingSMTP(ctx, cfg.Keys.EncryptionKey(), deps.Pool, deps.Redis, cfg.SMTPAllowedTargets)
	if err != nil {
		return nil, err
	}
	setupConfig := &config.Config{
		Account:      accountservice.Config{EncryptionKey: cfg.Keys.EncryptionKey()},
		InitialSetup: accountservice.SetupConfig{Enabled: true, Secret: cfg.Keys.SetupSecret()},
		MFA:          mfaservice.Config{Enabled: true, Issuer: p.Slug},
	}
	setup, err := security.assembleSetup(accountpostgres.New(deps.Pool), deps.Redis, mail, deps.Hash, setupConfig, deps.Logger)
	if err != nil {
		return nil, err
	}
	if err := admit(ctx); err != nil {
		return nil, err
	}
	return router.NewProjectOnboarding(router.ProjectOnboardingHTTP{
		Origin: p.Origin, Setup: setup, Capacity: cfg.HTTP, Proxy: cfg.Proxy, Logger: deps.Logger, Admit: deps.Admit,
	})
}

func (cfg ProjectOnboardingConfig) validate() error {
	p := cfg.Project
	if !projectdomain.ValidID(p.ID) || !projectdomain.ValidSlug(p.Slug) || !projectdomain.ValidOrigin(p.Origin) ||
		p.DesiredState != projectdomain.Enabled || p.Phase != projectdomain.Provisioning || p.Version < 1 || p.Generation < 1 ||
		cfg.Keys.Binding().ProjectID != p.ID || cfg.Keys.EncryptionKey() == "" || cfg.Keys.SetupSecret() == "" {
		return errors.New("incomplete project onboarding configuration")
	}
	if err := cfg.HTTP.Validate(); err != nil {
		return err
	}
	return cfg.Proxy.Validate()
}

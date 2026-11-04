package onboarding

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/repository/postgres"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
	setupapp "github.com/Inforberi/financial-intelligence/internal/app/auth/setup"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	accountsetup "github.com/Inforberi/financial-intelligence/internal/auth/account/setup/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type ProjectOnboardingConfig struct {
	Project            projectdomain.Project
	Reservation        projectdomain.PreparationReservation
	Keys               credentials.OnboardingKeys
	SMTPAllowedTargets []string
	HTTP               requestmiddleware.CapacityConfig
	Proxy              requestmiddleware.ProxyConfig
}

// Dependencies are borrowed; constructing or rejecting a runtime never closes them.
type ProjectOnboardingDependencies struct {
	Pool    *pgxpool.Pool
	Catalog *pgxpool.Pool
	Redis   *redis.Client
	Logger  *zap.Logger
	Hash    *hasher.Bounded
}

func NewProjectOnboarding(ctx context.Context, cfg ProjectOnboardingConfig, deps ProjectOnboardingDependencies) (http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	admission, err := preparationpostgres.NewOnboardingAdmission(deps.Catalog, cfg.Project, cfg.Reservation, cfg.Keys.Binding())
	if err != nil {
		return nil, err
	}
	p := cfg.Project
	scope, err := realmscope.New("project", string(p.ID))
	if err != nil {
		return nil, err
	}
	if deps.Pool == nil || deps.Redis == nil || deps.Logger == nil || deps.Hash == nil || !scope.Valid() {
		return nil, errors.New("auth realm requires pool, Redis, logger, shared hasher and explicit scope")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	operator, err := operatorpostgres.New(deps.Catalog, operatordomain.RealmID(cfg.Keys.Binding().RealmID))
	if err != nil {
		return nil, err
	}
	if err := operator.CheckRuntime(ctx, false); err != nil {
		return nil, err
	}
	admit := func(check context.Context) error {
		allowed, err := admission.Check(check)
		if err != nil || !allowed || check.Err() != nil {
			return errors.New("project onboarding unavailable")
		}
		return nil
	}
	if err := admit(ctx); err != nil {
		return nil, err
	}
	if err := schemapostgres.CheckOnboardingRuntime(ctx, deps.Pool, cfg.Keys.Proof()); err != nil {
		return nil, err
	}

	mail, err := projectOnboardingSMTP(ctx, scope, cfg.Keys.EncryptionKey(), deps.Pool, deps.Redis, cfg.SMTPAllowedTargets)
	if err != nil {
		return nil, err
	}
	setupConfig := &config.Config{
		Account:      accountservice.Config{EncryptionKey: cfg.Keys.EncryptionKey()},
		InitialSetup: accountsetup.SetupConfig{Enabled: true, Secret: cfg.Keys.SetupSecret()},
		MFA:          mfaservice.Config{Enabled: true, Issuer: p.Slug},
	}
	setup, err := setupapp.Assemble(scope, accountpostgres.New(deps.Pool), deps.Redis, mail, deps.Hash, setupConfig, deps.Logger)
	if err != nil {
		return nil, err
	}
	if err := admit(ctx); err != nil {
		return nil, err
	}
	return router.NewProjectOnboarding(router.ProjectOnboardingHTTP{
		Origin: p.Origin, Setup: setup, Capacity: cfg.HTTP, Proxy: cfg.Proxy, Logger: deps.Logger, Admit: admission.Check,
	})
}

func (cfg ProjectOnboardingConfig) validate() error {
	p := cfg.Project
	if !p.AllowsOnboarding() ||
		cfg.Keys.Binding().ProjectID != p.ID || cfg.Keys.EncryptionKey() == "" || cfg.Keys.SetupSecret() == "" {
		return errors.New("incomplete project onboarding configuration")
	}
	if err := cfg.HTTP.Validate(); err != nil {
		return err
	}
	return cfg.Proxy.Validate()
}

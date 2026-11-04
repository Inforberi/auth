package auth

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/admission"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	adminapp "github.com/Inforberi/financial-intelligence/internal/app/admin"
	setupapp "github.com/Inforberi/financial-intelligence/internal/app/auth/setup"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func assembleOperator(ctx context.Context, cfg *config.Config, deps Dependencies, mail accountservice.Mailer) (*Runtime, error) {
	operator, security, err := administrationAuthority(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	owned := &Resources{}
	assembled := false
	defer func() {
		if !assembled {
			owned.Close()
		}
	}()
	runtime, err := projectapp.Open(ctx, cfg.Platform, owned)
	if err != nil {
		return nil, err
	}
	delivery, err := assembleProjectDelivery(cfg.Platform, runtime, deps.Redis)
	if err != nil {
		return nil, err
	}
	var observer projectservice.RuntimeObserver
	if runtime != nil {
		observer = runtime
	}
	accountRuntime, err := security.assembleAccount(deps.Pool, deps.Redis, mail, cfg.Account, postgres.DeliveryConfig{})
	if err != nil {
		return nil, err
	}
	account, repo := accountRuntime.verification, accountRuntime.repository
	setup, err := setupapp.Assemble(security.scope, operator, deps.Redis, mail, deps.Hash, cfg, deps.Logger)
	if err != nil {
		return nil, err
	}
	sessions := sessionpostgres.New(deps.Pool)
	tokens := tokengenerate.New()
	svc := sessionservice.New(clock.UTCClock{}, sessions, tokens, cfg.Session)
	mfa, err := security.assembleMFA(ctx, deps.Pool, deps.Redis, svc, tokens, mail, cfg, deps.Logger)
	if err != nil {
		return nil, err
	}
	credentials := passwordpostgres.New(deps.Pool)
	policy := settingsservice.New(settingspostgres.New(deps.Pool))
	password, err := security.assemblePassword(credentials, deps.Redis, mfa.sessions, deps.Hash, policy, mail, cfg)
	if err != nil {
		return nil, err
	}
	projects, err := projectpostgres.NewManaged(deps.Pool, operator, cfg.Session.FreshAuthTTL, projectdomain.CreationPolicy{
		AuthDomain: cfg.Platform.ProjectAuthDomain, StorageTarget: cfg.Platform.StorageTarget, PlatformOrigin: cfg.Platform.Origin,
	})
	if err != nil {
		return nil, err
	}
	capacity, err := admission.New(deps.Redis, projectdomain.ID(cfg.Platform.RealmID), cfg.Platform.Operations)
	if err != nil {
		return nil, err
	}
	var registry *projectruntime.Registry
	if runtime != nil {
		registry = runtime.Registry
	}
	roles, err := adminapp.ProjectRoles(cfg, registry, projects, deps.Logger)
	if err != nil {
		return nil, err
	}
	projectHTTP, drainHTTP, err := openProjectHTTP(ctx, cfg, runtime, delivery, deps, owned)
	if err != nil {
		return nil, err
	}
	var readiness policypostgres.AuthPolicyReadinessSource
	if projectHTTP != nil {
		readiness = projectHTTP.Assess
	}
	handler, err := router.NewOperator(router.Handlers{
		Config: cfg, Logger: deps.Logger, Setup: setup, MFA: mfa.handler, MFALogin: mfa.loginHandler, MFARecovery: mfa.recoveryHandler,
		Projects:          projecthttp.New(projectservice.NewWithRuntime(projects, operator, observer), deps.Logger),
		ProjectRoles:      roles,
		ProjectUsers:      adminapp.ProjectUsers(registry, projects, deps.Logger),
		ProjectAuthPolicy: adminapp.ProjectAuthPolicy(registry, projects, readiness, deps.Logger),
		ProjectCapacity:   projecthttp.Capacity(capacity),
		MFASettings:       adminapp.MFASettings(operator, cfg.MFA.Enabled, deps.Logger),
		PasswordHandler:   passwordhttp.New(password.service, deps.Logger),
		Recovery:          passwordrecoveryhttp.NewRecovery(password.recovery, deps.Logger),
		Middleware:        sessionhttp.New(svc, deps.Logger),
		Session:           sessionhttp.NewHandler(sessionservice.NewManagement(sessions), deps.Logger),
		Activity:          sessionhttp.NewActivity(sessionservice.NewActivity(sessions), deps.Logger),
		Rotation:          sessionhttp.NewRotation(sessionservice.NewRotation(sessions, tokens), deps.Logger),
		Reauthentication:  passwordhttp.NewReauthentication(passwordservice.NewReauthentication(credentials, sessions, deps.Hash, password.loginLimit, tokens, cfg.Session.FreshAuthTTL), deps.Logger),
		ReadyCheck:        operatorReadyCheck(deps, runtime),
	})
	if err != nil {
		return nil, err
	}
	workers := realmDeliveryWorkers(password.recovery, account, mfa.delivery, nil, delivery)
	handler = projectHostRouter(cfg.Platform.Origin, handler, projectHTTP)
	assembled = true
	return &Runtime{
		Handler: handler, resources: owned,
		drainHTTP: drainHTTP,
		retention: accountservice.NewRetention(repo, cfg.Retention),
		workers:   workers,
	}, nil
}

func operatorReadyCheck(deps Dependencies, runtime *projectapp.Runtime) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := deps.Pool.Ping(ctx); err != nil {
			return err
		}
		if runtime != nil {
			if err := runtime.Reader.CheckRuntime(ctx); err != nil {
				return err
			}
		}
		return deps.Redis.Ping(ctx).Err()
	}
}

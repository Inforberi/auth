package admin

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/admission"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	authapp "github.com/Inforberi/financial-intelligence/internal/app/auth"
	accountapp "github.com/Inforberi/financial-intelligence/internal/app/auth/account"
	methodapp "github.com/Inforberi/financial-intelligence/internal/app/auth/methods"
	mfaapp "github.com/Inforberi/financial-intelligence/internal/app/auth/mfa"
	setupapp "github.com/Inforberi/financial-intelligence/internal/app/auth/setup"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
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

func Assemble(ctx context.Context, cfg *config.Config, deps authapp.Dependencies, mail accountservice.Mailer) (*authapp.Runtime, error) {
	operator, scope, err := administrationAuthority(ctx, cfg, deps)
	if err != nil {
		return nil, err
	}
	owned := &authapp.Resources{}
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
	repo := postgres.NewWithDelivery(deps.Pool, postgres.DeliveryConfig{})
	accountRuntime, err := accountapp.Assemble(scope, repo, deps.Redis, mail, cfg.Account)
	if err != nil {
		return nil, err
	}
	account := accountRuntime.Verification
	setup, err := setupapp.Assemble(scope, operator, deps.Redis, mail, deps.Hash, cfg, deps.Logger)
	if err != nil {
		return nil, err
	}
	sessions := sessionpostgres.New(deps.Pool)
	tokens := tokengenerate.New()
	svc := sessionservice.New(clock.UTCClock{}, sessions, tokens, cfg.Session)
	mfa, err := mfaapp.Assemble(ctx, scope, deps.Pool, deps.Redis, svc, tokens, mail, cfg, deps.Logger)
	if err != nil {
		return nil, err
	}
	credentials := passwordpostgres.New(deps.Pool)
	policy := settingsservice.New(settingspostgres.New(deps.Pool))
	password, err := methodapp.AssemblePassword(scope, credentials, deps.Redis, mfa.Sessions, deps.Hash, policy, mail, cfg)
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
	roles, err := ProjectRoles(cfg, registry, projects, deps.Logger)
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
		Config: cfg, Logger: deps.Logger, Setup: setup, MFA: mfa.Handler, MFALogin: mfa.LoginHandler, MFARecovery: mfa.RecoveryHandler,
		Projects:          projecthttp.New(projectservice.NewWithRuntime(projects, operator, observer), deps.Logger),
		ProjectRoles:      roles,
		ProjectUsers:      ProjectUsers(registry, projects, deps.Logger),
		ProjectAuthPolicy: ProjectAuthPolicy(registry, projects, readiness, deps.Logger),
		ProjectCapacity:   projecthttp.Capacity(capacity),
		MFASettings:       MFASettings(operator, cfg.MFA.Enabled, deps.Logger),
		PasswordHandler:   passwordhttp.New(password.Service, deps.Logger),
		Recovery:          passwordrecoveryhttp.NewRecovery(password.Recovery, deps.Logger),
		Middleware:        sessionhttp.New(svc, deps.Logger),
		Session:           sessionhttp.NewHandler(sessionservice.NewManagement(sessions), deps.Logger),
		Activity:          sessionhttp.NewActivity(sessionservice.NewActivity(sessions), deps.Logger),
		Rotation:          sessionhttp.NewRotation(sessionservice.NewRotation(sessions, tokens), deps.Logger),
		Reauthentication:  password.Reauthentication(credentials, sessions, deps.Hash, tokens, cfg.Session.FreshAuthTTL, deps.Logger),
		ReadyCheck:        operatorReadyCheck(deps, runtime),
	})
	if err != nil {
		return nil, err
	}
	workers := authapp.DeliveryWorkers(password.Recovery, account, mfa.Delivery, nil, delivery)
	if projectHTTP != nil {
		handler = router.ProjectHosts(cfg.Platform.Origin, handler, projectHTTP)
	}
	assembled = true
	return authapp.NewRuntime(handler, accountservice.NewRetention(repo, cfg.Retention), workers, owned, drainHTTP), nil
}

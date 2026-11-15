package admin

import (
	"time"

	"go.uber.org/zap"

	policypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	policyservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/service"
	policyhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/transport/http"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	authsettings "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func ProjectAuthPolicy(runtime *projectruntime.Registry, repo *projectpostgres.Repository, readiness policypostgres.AuthPolicyReadinessSource, log *zap.Logger, cfg *config.Config, profiles ...policypostgres.SettingsProfile) *policyhttp.AuthPolicyHandler {
	if runtime == nil {
		return nil
	}
	// The disabled HTTP profile keeps all public capabilities closed.
	available := settingsdomain.PolicyRuntime{Configured: true}
	linkDefaults := settingsdomain.LinkLifetimePolicy{
		VerificationSeconds: int64(cfg.Account.TTL / time.Second),
		ResetSeconds:        int64(cfg.Password.ResetTokenTTL / time.Second),
	}
	backend := policypostgres.NewRuntimeAuthPolicy(repo, runtime, available).
		WithBrowserSessionBaseline(cfg.Session.BrowserPolicy()).
		WithLinkLifetimeBaseline(linkDefaults, int64(cfg.Account.ResendInterval/time.Second)).
		WithCredentialLifetimeBaseline(authsettings.CredentialLifetimeBaseline(cfg)).
		WithLoginBudgetBaseline(authsettings.LoginBudgetBaseline(cfg)).
		WithOperationBudgetBaseline(authsettings.OperationBudgetBaseline(cfg))
	if len(profiles) > 0 {
		backend.WithSettingsProfile(profiles[0])
	}
	if readiness == nil {
		return policyhttp.NewAuthPolicy(policyservice.NewAuthPolicy(backend), available.Methods, log).WithProjectMFA(backend).WithProjectRetention(backend).WithProjectDelivery(backend).WithProjectTelegramBot(backend).WithProjectSessions(backend).WithProjectLinkLifetimes(backend).WithProjectCredentialLifetimes(backend).WithProjectLoginBudgets(backend).WithProjectOperationBudgets(backend).WithProjectFrontends(backend)
	}
	backend = backend.WithReadiness(readiness)
	return policyhttp.NewAuthPolicyWithReadiness(policyservice.NewAuthPolicyWithReadiness(backend), log).WithProjectMFA(backend).WithProjectRetention(backend).WithProjectDelivery(backend).WithProjectTelegramBot(backend).WithProjectSessions(backend).WithProjectLinkLifetimes(backend).WithProjectCredentialLifetimes(backend).WithProjectLoginBudgets(backend).WithProjectOperationBudgets(backend).WithProjectFrontends(backend)
}

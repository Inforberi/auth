package admin

import (
	"go.uber.org/zap"

	policypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	policyservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/service"
	policyhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/transport/http"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func ProjectAuthPolicy(runtime *projectruntime.Registry, repo *projectpostgres.Repository, readiness policypostgres.AuthPolicyReadinessSource, log *zap.Logger) *policyhttp.AuthPolicyHandler {
	if runtime == nil {
		return nil
	}
	// The disabled HTTP profile keeps all public capabilities closed.
	available := settingsdomain.PolicyRuntime{Configured: true}
	backend := policypostgres.NewRuntimeAuthPolicy(repo, runtime, available)
	if readiness == nil {
		return policyhttp.NewAuthPolicy(policyservice.NewAuthPolicy(backend), available.Methods, log)
	}
	backend = backend.WithReadiness(readiness)
	return policyhttp.NewAuthPolicyWithReadiness(policyservice.NewAuthPolicyWithReadiness(backend), log)
}

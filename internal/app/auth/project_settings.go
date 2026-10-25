package auth

import (
	"go.uber.org/zap"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

func assembleProjectAuthPolicy(runtime *projectRuntime, repo *projectpostgres.Repository, project *ProjectHTTP, log *zap.Logger) *projecthttp.AuthPolicyHandler {
	if runtime == nil {
		return nil
	}
	// The disabled HTTP profile keeps all public capabilities closed.
	available := settingsdomain.PolicyRuntime{Configured: true}
	backend := projectpostgres.NewRuntimeAuthPolicy(repo, runtime.registry, available)
	if project == nil {
		return projecthttp.NewAuthPolicy(projectservice.NewAuthPolicy(backend), available.Methods, log)
	}
	backend = backend.WithReadiness(project.Assess)
	return projecthttp.NewAuthPolicyWithReadiness(projectservice.NewAuthPolicyWithReadiness(backend), log)
}

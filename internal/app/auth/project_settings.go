package auth

import (
	"go.uber.org/zap"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

func assembleProjectAuthPolicy(runtime *projectRuntime, repo *projectpostgres.Repository, log *zap.Logger) *projecthttp.AuthPolicyHandler {
	if runtime == nil {
		return nil
	}
	// SQL connectivity is not assembled Auth/delivery/provider/token capability.
	available := settingsdomain.PolicyRuntime{Configured: true}
	backend := projectpostgres.NewRuntimeAuthPolicy(repo, runtime.registry, available)
	return projecthttp.NewAuthPolicy(projectservice.NewAuthPolicy(backend), available.Methods, log)
}

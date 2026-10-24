package auth

import (
	"go.uber.org/zap"

	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

func assembleProjectUsers(runtime *projectRuntime, repo *projectpostgres.Repository, log *zap.Logger) *projecthttp.UserHandler {
	if runtime == nil {
		return nil
	}
	backend := projectpostgres.NewRuntimeUsers(repo, runtime.registry)
	return projecthttp.NewUsers(projectservice.NewUsers(backend), log)
}

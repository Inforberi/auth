package auth

import (
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
)

func assembleProjectRoles(cfg *config.Config, runtime *projectRuntime, repo *projectpostgres.Repository, log *zap.Logger) (*projecthttp.RoleHandler, error) {
	if runtime == nil {
		return nil, nil
	}
	definition, err := settings.LoadFile(cfg.Access.CatalogFile)
	if err != nil {
		return nil, err
	}
	backend := projectpostgres.NewRuntimeRoles(repo, runtime.registry, definition.Catalog())
	return projecthttp.NewRoles(projectservice.NewRoles(backend), log), nil
}

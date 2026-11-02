package admin

import (
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	rolespostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/repository/postgres"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
	roleshttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/transport/http"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func ProjectRoles(cfg *config.Config, runtime *projectruntime.Registry, repo *projectpostgres.Repository, log *zap.Logger) (*roleshttp.RoleHandler, error) {
	if runtime == nil {
		return nil, nil
	}
	definition, err := settings.LoadFile(cfg.Access.CatalogFile)
	if err != nil {
		return nil, err
	}
	backend := rolespostgres.NewRuntimeRoles(repo, runtime, definition.Catalog())
	return roleshttp.NewRoles(roleservice.NewRoles(backend), log), nil
}

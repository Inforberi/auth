package admin

import (
	"go.uber.org/zap"

	directorypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/repository/postgres"
	directoryservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/service"
	directoryhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/directory/transport/http"
	projectpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

func ProjectUsers(runtime *projectruntime.Registry, repo *projectpostgres.Repository, log *zap.Logger) *directoryhttp.UserHandler {
	if runtime == nil {
		return nil
	}
	backend := directorypostgres.NewRuntimeUsers(repo, runtime)
	return directoryhttp.NewUsers(directoryservice.NewUsers(backend), log)
}

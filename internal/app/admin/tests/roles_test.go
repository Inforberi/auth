package admin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	adminapp "github.com/Inforberi/financial-intelligence/internal/app/admin"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectRoleHTTPRequiresRuntime(t *testing.T) {
	handler, err := adminapp.ProjectRoles(&config.Config{}, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, handler)
	cfg := &config.Config{}
	cfg.Access.CatalogFile = t.TempDir() + "/missing-catalog.json"
	_, err = adminapp.ProjectRoles(cfg, &projectruntime.Registry{}, nil, nil)
	require.Error(t, err, "invalid catalog must stop assembly before routes are published")
}

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectRoleHTTPRequiresRuntime(t *testing.T) {
	handler, err := assembleProjectRoles(&config.Config{}, nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, handler)
	cfg := &config.Config{}
	cfg.Access.CatalogFile = t.TempDir() + "/missing-catalog.json"
	_, err = assembleProjectRoles(cfg, &projectRuntime{}, nil, nil)
	require.Error(t, err, "invalid catalog must stop assembly before routes are published")
}

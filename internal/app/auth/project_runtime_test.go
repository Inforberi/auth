package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestDisabledProjectRuntimeOwnsNoResources(t *testing.T) {
	owned := &Resources{}
	runtime, err := projectapp.Open(t.Context(), config.PlatformConfig{}, owned)
	require.NoError(t, err)
	require.Nil(t, runtime)
	require.Empty(t, owned.closers)
	owned.Close()
}

func TestProjectStorageTransportFailsBeforeCatalogConnection(t *testing.T) {
	for _, c := range []config.ProjectRuntimeConfig{
		{Enabled: true, StorageHost: "host,other", StoragePort: 5432},
		{Enabled: true, StorageHost: "/var/run/postgresql", StoragePort: 5432, StorageCAFile: "invalid"},
		{Enabled: true, StorageHost: "db.example", StoragePort: 5432, StorageCAFile: t.TempDir()},
	} {
		owned := &Resources{}
		_, err := projectapp.Open(t.Context(), config.PlatformConfig{Runtime: c}, owned)
		require.Error(t, err)
		require.Empty(t, owned.closers)
	}
}

package auth

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestDisabledProjectRuntimeOwnsNoResources(t *testing.T) {
	owned := &resources{}
	runtime, err := openProjectRuntime(t.Context(), config.PlatformConfig{}, owned)
	require.NoError(t, err)
	require.Nil(t, runtime)
	require.Empty(t, owned.closers)
	owned.close()
}

func TestProjectStorageTransportFailsBeforeCatalogConnection(t *testing.T) {
	for _, c := range []config.ProjectRuntimeConfig{
		{Enabled: true, StorageHost: "host,other", StoragePort: 5432},
		{Enabled: true, StorageHost: "/var/run/postgresql", StoragePort: 5432, StorageCAFile: "invalid"},
		{Enabled: true, StorageHost: "db.example", StoragePort: 5432, StorageCAFile: t.TempDir()},
	} {
		owned := &resources{}
		_, err := openProjectRuntime(t.Context(), config.PlatformConfig{Runtime: c}, owned)
		require.Error(t, err)
		require.Empty(t, owned.closers)
	}
}

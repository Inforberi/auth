package config

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformSQLBudget(t *testing.T) {
	cfg := validConfig()
	cfg.Postgres.MaxConns = 10
	cfg.Platform.Resources = DefaultPlatformResources()
	cfg.Platform.Runtime = ProjectRuntimeConfig{Enabled: true, MaxRuntimes: 8, ConnectionsPerProject: 4}
	// Each API needs 10 public + 2 private catalog + 32 project connections.
	cfg.Platform.Resources.APIInstances = 2
	cfg.Platform.Resources.SQLConnections = 92
	require.NoError(t, cfg.validatePlatformResources())
	cfg.Platform.Resources.SQLConnections = 91
	require.Error(t, cfg.validatePlatformResources())
	cfg.Platform.Resources.SQLConnections = 92
	cfg.Platform.Resources.APIInstances = 3
	require.Error(t, cfg.validatePlatformResources(), "rolling surge must fit too")
	cfg.Platform.Runtime.Enabled = false
	require.NoError(t, cfg.validatePlatformResources(), "disabled runtime allocates no private/project pools")
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Platform.Resources.APIInstances = 0 },
		func(c *Config) { c.Platform.Resources.ExternalReserve = c.Platform.Resources.SQLConnections },
		func(c *Config) { c.Platform.Resources.SQLConnections = math.MaxInt },
		func(c *Config) { c.Postgres.MaxConns = 1000 },
		func(c *Config) {
			c.Platform.Runtime.Enabled = true
			c.Platform.Runtime.MaxRuntimes = math.MaxInt
			c.Platform.Runtime.ConnectionsPerProject = math.MaxInt32
		},
	} {
		c := cfg
		mutate(&c)
		require.Error(t, c.validatePlatformResources())
	}
}

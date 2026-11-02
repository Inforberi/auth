package config

import (
	"errors"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type PlatformResources struct {
	APIInstances    int `env:"PLATFORM_API_INSTANCES" env-default:"1"`
	SQLConnections  int `env:"PLATFORM_SQL_CONNECTION_BUDGET" env-default:"80"`
	ExternalReserve int `env:"PLATFORM_SQL_EXTERNAL_RESERVE" env-default:"4"`
}

func DefaultPlatformResources() PlatformResources {
	return PlatformResources{APIInstances: 1, SQLConnections: 80, ExternalReserve: 4}
}

func (cfg Config) validatePlatformResources() error {
	c := cfg.Platform.Resources
	if c.APIInstances < 1 || c.APIInstances > 1000 || c.SQLConnections < 1 || c.SQLConnections > 1_000_000 || c.ExternalReserve < 0 || c.ExternalReserve >= c.SQLConnections || cfg.Postgres.MaxConns < 1 {
		return errors.New("invalid platform instance/SQL connection budget")
	}
	perInstance := (c.SQLConnections - c.ExternalReserve) / c.APIInstances
	catalog := int64(cfg.Postgres.MaxConns)
	if cfg.Platform.Runtime.Enabled {
		catalog += int64(projectruntime.ReaderMaxConnections)
	}
	if catalog > int64(perInstance) {
		return errors.New("catalog pools exceed declared platform SQL budget")
	}
	if cfg.Platform.Runtime.Enabled {
		runtime := cfg.Platform.Runtime
		remaining := int64(perInstance) - catalog
		if int64(runtime.MaxRuntimes) > remaining/int64(runtime.ConnectionsPerProject) {
			return errors.New("project pools exceed declared platform SQL budget across API instances")
		}
	}
	return nil
}

package config

import (
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/infra/postgres"
)

type ProjectRuntimeConfig struct {
	Enabled               bool          `env:"PLATFORM_PROJECT_RUNTIME_ENABLED" env-default:"false"`
	CatalogURL            string        `env:"PLATFORM_RUNTIME_CATALOG_URL" json:"-"`
	MasterKey             string        `env:"PLATFORM_PROJECT_MASTER_KEY" json:"-"`
	MasterKeyID           string        `env:"PLATFORM_PROJECT_MASTER_KEY_ID"`
	StorageHost           string        `env:"PLATFORM_STORAGE_HOST"`
	StoragePort           uint16        `env:"PLATFORM_STORAGE_PORT" env-default:"5432"`
	StorageCAFile         string        `env:"PLATFORM_STORAGE_CA_FILE"`
	MaxRuntimes           int           `env:"PLATFORM_PROJECT_MAX_RUNTIMES" env-default:"8"`
	ConnectionsPerProject int32         `env:"PLATFORM_PROJECT_MAX_CONNECTIONS" env-default:"4"`
	ConnectionBudget      int           `env:"PLATFORM_PROJECT_SQL_BUDGET" env-default:"32"`
	MaxAcquiring          int           `env:"PLATFORM_PROJECT_MAX_ACQUIRING" env-default:"64"`
	AcquireTimeout        time.Duration `env:"PLATFORM_PROJECT_ACQUIRE_TIMEOUT" env-default:"2s"`
	OpenTimeout           time.Duration `env:"PLATFORM_PROJECT_OPEN_TIMEOUT" env-default:"2s"`
	IdleTimeout           time.Duration `env:"PLATFORM_PROJECT_IDLE_TIMEOUT" env-default:"5m"`
	SyncInterval          time.Duration `env:"PLATFORM_PROJECT_SYNC_INTERVAL" env-default:"5s"`
	SyncTimeout           time.Duration `env:"PLATFORM_PROJECT_SYNC_TIMEOUT" env-default:"2s"`
}

func (c ProjectRuntimeConfig) Registry() projectruntime.Config {
	return projectruntime.Config{
		MaxRuntimes: c.MaxRuntimes, ConnectionsPerProject: c.ConnectionsPerProject, ConnectionBudget: c.ConnectionBudget,
		MaxAcquiring: c.MaxAcquiring, AcquireTimeout: c.AcquireTimeout, OpenTimeout: c.OpenTimeout, IdleTimeout: c.IdleTimeout,
	}
}

func (c ProjectRuntimeConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !c.Registry().Valid() || c.StorageHost == "" || c.StoragePort == 0 {
		return errors.New("platform project runtime requires a storage host/port and valid bounded SQL budgets")
	}
	if c.SyncInterval < time.Second || c.SyncInterval > time.Minute || c.SyncTimeout <= 0 || c.SyncTimeout > 3*time.Second {
		return errors.New("PLATFORM_PROJECT_SYNC_INTERVAL must be 1s..1m and PLATFORM_PROJECT_SYNC_TIMEOUT within (0,3s]")
	}
	if _, err := postgres.TrustedConfig(c.CatalogURL); err != nil {
		return errors.New("PLATFORM_RUNTIME_CATALOG_URL requires one explicit trusted endpoint")
	}
	if _, err := credentials.New(c.MasterKey, c.MasterKeyID); err != nil {
		return errors.New("platform project runtime requires valid PLATFORM_PROJECT_MASTER_KEY and KEY_ID")
	}
	return nil
}

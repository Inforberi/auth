package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProjectRuntimeConfiguration(t *testing.T) {
	base := ProjectRuntimeConfig{
		Enabled: true, CatalogURL: "postgres://reader@/catalog?host=/var/run/postgresql&sslmode=disable",
		MasterKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), MasterKeyID: "root-1",
		StorageHost: "storage.example", StoragePort: 5432, MaxRuntimes: 2, ConnectionsPerProject: 2, ConnectionBudget: 4,
		MaxAcquiring: 8, AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute,
		SyncInterval: 5 * time.Second, SyncTimeout: 2 * time.Second,
	}
	require.NoError(t, base.Validate())
	for name, mutate := range map[string]func(*ProjectRuntimeConfig){
		"budget": func(c *ProjectRuntimeConfig) { c.ConnectionBudget = 3 },
		"key":    func(c *ProjectRuntimeConfig) { c.MasterKey = "secret-invalid" },
		"key id": func(c *ProjectRuntimeConfig) { c.MasterKeyID = "" },
		"catalog transport": func(c *ProjectRuntimeConfig) {
			c.CatalogURL = "postgres://reader:secret@db.example/catalog?sslmode=disable"
		},
		"host":          func(c *ProjectRuntimeConfig) { c.StorageHost = "" },
		"port":          func(c *ProjectRuntimeConfig) { c.StoragePort = 0 },
		"wait":          func(c *ProjectRuntimeConfig) { c.AcquireTimeout = 0 },
		"sync interval": func(c *ProjectRuntimeConfig) { c.SyncInterval = 0 },
		"sync timeout":  func(c *ProjectRuntimeConfig) { c.SyncTimeout = 4 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			err := c.Validate()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret")
		})
	}
	base.Enabled = false
	base.MasterKey, base.CatalogURL = "", ""
	require.NoError(t, base.Validate())
	cfg := Config{Platform: PlatformConfig{Runtime: ProjectRuntimeConfig{Enabled: true}}}
	require.Error(t, cfg.ValidatePlatform(), "runtime cannot silently run in standalone mode")
}

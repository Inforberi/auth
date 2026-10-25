package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProjectHTTPDeploymentBounds(t *testing.T) {
	require.NoError(t, (Config{}).validateProjectHTTP())
	cfg := Config{}
	cfg.Platform.Enabled, cfg.Platform.Runtime.Enabled = true, true
	cfg.Platform.Runtime.MaxAcquiring = 64
	cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile = "cert.pem", "key.pem"
	cfg.HTTP.RequestTimeout = 10 * time.Second
	cfg.Platform.HTTP = ProjectHTTPConfig{Enabled: true, MaxProfiles: 8, MaxBuilding: 2, BuildTimeout: 5 * time.Second, MaxAge: 30 * time.Second, MaxInFlight: 32}
	require.NoError(t, cfg.validateProjectHTTP())
	for name, mutate := range map[string]func(*Config){
		"no platform": func(c *Config) { c.Platform.Enabled = false },
		"no runtime":  func(c *Config) { c.Platform.Runtime.Enabled = false },
		"no TLS":      func(c *Config) { c.Server.TLSKeyFile = "" },
		"profiles":    func(c *Config) { c.Platform.HTTP.MaxProfiles = 257 },
		"builders":    func(c *Config) { c.Platform.HTTP.MaxBuilding = 9 },
		"deadline":    func(c *Config) { c.Platform.HTTP.BuildTimeout = 11 * time.Second },
		"age":         func(c *Config) { c.Platform.HTTP.MaxAge = 0 },
		"admission":   func(c *Config) { c.Platform.HTTP.MaxInFlight = 33 },
	} {
		t.Run(name, func(t *testing.T) { broken := cfg; mutate(&broken); require.Error(t, broken.validateProjectHTTP()) })
	}
}

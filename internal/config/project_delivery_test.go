package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProjectDeliveryConfiguration(t *testing.T) {
	base := Config{Platform: PlatformConfig{
		Enabled: true, Runtime: ProjectRuntimeConfig{Enabled: true, MaxAcquiring: 8, MaxRuntimes: 2}, Resources: PlatformResources{APIInstances: 2},
		Delivery: ProjectDeliveryConfig{Enabled: true, Parallelism: 2, PageSize: 4, Interval: 5 * time.Second, FleetConcurrency: 4, SMTPAllowedTargets: "smtp.example.test:587, [::1]:2525"},
	}}
	require.NoError(t, base.validateProjectDelivery())
	require.Equal(t, []string{"smtp.example.test:587", "[::1]:2525"}, base.Platform.Delivery.Targets())
	for name, change := range map[string]func(*Config){
		"platform disabled":     func(c *Config) { c.Platform.Enabled = false },
		"runtime disabled":      func(c *Config) { c.Platform.Runtime.Enabled = false },
		"no workers":            func(c *Config) { c.Platform.Delivery.Parallelism = 0 },
		"small page":            func(c *Config) { c.Platform.Delivery.PageSize = 1 },
		"large page":            func(c *Config) { c.Platform.Delivery.PageSize = 100000 },
		"hot loop":              func(c *Config) { c.Platform.Delivery.Interval = time.Millisecond },
		"long interval":         func(c *Config) { c.Platform.Delivery.Interval = 2 * time.Minute },
		"lease reserve":         func(c *Config) { c.Platform.Runtime.MaxAcquiring = 3 },
		"resident reserve":      func(c *Config) { c.Platform.Runtime.MaxRuntimes = 1 },
		"fleet surge":           func(c *Config) { c.Platform.Resources.APIInstances = 3 },
		"fleet zero":            func(c *Config) { c.Platform.Delivery.FleetConcurrency = 0 },
		"no declared instances": func(c *Config) { c.Platform.Resources.APIInstances = 0 },
		"empty allowlist":       func(c *Config) { c.Platform.Delivery.SMTPAllowedTargets = "" },
		"URI instead of target": func(c *Config) { c.Platform.Delivery.SMTPAllowedTargets = "smtp://user:secret@smtp.example.test:587" },
		"port overflow":         func(c *Config) { c.Platform.Delivery.SMTPAllowedTargets = "smtp.example.test:65536" },
		"too many targets":      func(c *Config) { c.Platform.Delivery.SMTPAllowedTargets = strings.Repeat("smtp.example.test:587,", 17) },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			change(&cfg)
			err := cfg.validateProjectDelivery()
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret")
		})
	}
	cfg := Config{Platform: PlatformConfig{Delivery: base.Platform.Delivery}}
	require.Error(t, cfg.ValidatePlatform(), "delivery must not silently run in standalone mode")
	cfg.Platform.Delivery.Enabled = false
	require.NoError(t, cfg.ValidatePlatform(), "disabled ignores delivery-only settings")
	cfg = base
	cfg.Platform.Delivery.Enabled = false
	cfg.Platform.Delivery.SMTPAllowedTargets = "invalid"
	cfg.Platform.Delivery.Interval = 0
	require.NoError(t, cfg.validateProjectDelivery())
}

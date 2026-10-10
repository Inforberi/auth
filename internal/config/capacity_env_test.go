package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func TestCapacityEnvironment(t *testing.T) {
	t.Setenv("HTTP_MAX_IN_FLIGHT", "64")
	t.Setenv("HTTP_REQUEST_TIMEOUT", "8s")
	t.Setenv("HTTP_TRUSTED_PROXY_CIDRS", "")
	t.Setenv("PASSWORD_HASH_CONCURRENCY", "4")
	t.Setenv("LOGIN_IP_LIMIT", "60")
	t.Setenv("LOGIN_EMAIL_LIMIT", "20")
	t.Setenv("LOGIN_GLOBAL_LIMIT", "2000")
	var cfg struct {
		HTTP     requestmiddleware.CapacityConfig
		Proxy    requestmiddleware.ProxyConfig
		Password passwordservice.CapacityConfig
	}
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Proxy.Validate(); err != nil {
		t.Fatal("empty proxy env", err)
	}
	if cfg.HTTP.MaxInFlight != 64 || cfg.HTTP.RequestTimeout != 8*time.Second || cfg.Password.HashConcurrency != 4 || cfg.Password.LoginGlobalLimit != 2000 {
		t.Fatal("capacity env not applied", cfg)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Capacity.HashConcurrency = 0 },
		func(c *Config) { c.Capacity.HashConcurrency = 33 },
		func(c *Config) { c.Capacity.LoginGlobalLimit = 0 },
		func(c *Config) { c.HTTP.MaxInFlight = 0 },
		func(c *Config) { c.HTTP.RequestTimeout = 11 * time.Second },
		func(c *Config) { c.Proxy.TrustedCIDRs = []string{"invalid"} },
		func(c *Config) { c.Retention.BatchSize = 1001 },
		func(c *Config) { c.Retention.Interval = 0 },
		func(c *Config) { c.Account.RegistrationGlobalLimit = 0 },
		func(c *Config) { c.Password.ResetGlobalLimit = 0 },
	} {
		cfg := validConfig()
		mutate(&cfg)
		if cfg.Validate() == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
}

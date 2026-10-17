package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func readSession(cfg *sessionservice.Config) error { return cleanenv.ReadEnv(cfg) }

func TestAdministrativeSessionEnvironment(t *testing.T) {
	t.Setenv("ADMIN_SESSION_IDLE_TIMEOUT", "20m")
	t.Setenv("ADMIN_SESSION_ABSOLUTE_TTL", "8h")
	t.Setenv("ADMIN_SESSION_ACTIVITY_INTERVAL", "30s")
	var cfg sessionservice.Config
	if err := readSession(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AdminIdleTimeout != 20*time.Minute || cfg.AdminAbsoluteTTL != 8*time.Hour || cfg.AdminActivityInterval != 30*time.Second || cfg.SessionTTL != 168*time.Hour {
		t.Fatal("admin and public lifetime settings are not independent", cfg)
	}
}

func TestAdministrativeSessionDurations(t *testing.T) {
	for _, mutate := range []func(*sessionservice.Config){
		func(c *sessionservice.Config) { c.AdminIdleTimeout = 0 },
		func(c *sessionservice.Config) { c.AdminAbsoluteTTL = time.Minute },
		func(c *sessionservice.Config) { c.AdminActivityInterval = 0 },
		func(c *sessionservice.Config) { c.AdminActivityInterval = 4 * time.Minute },
		func(c *sessionservice.Config) { c.AdminIdleTimeout += time.Millisecond },
	} {
		cfg := validConfig()
		mutate(&cfg.Session)
		if err := cfg.validateSessions(); err == nil {
			t.Fatal("invalid admin lifetime accepted", cfg.Session)
		}
	}
}

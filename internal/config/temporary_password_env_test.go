package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

func TestTemporaryPasswordConfiguration(t *testing.T) {
	t.Setenv("TEMPORARY_PASSWORD_ENABLED", "true")
	t.Setenv("TEMPORARY_PASSWORD_TTL", "2h")
	t.Setenv("TEMPORARY_PASSWORD_SETUP_TTL", "5m")
	t.Setenv("TEMPORARY_PASSWORD_REISSUE_COOLDOWN", "2m")
	t.Setenv("TEMPORARY_PASSWORD_ISSUE_ACTOR_ATTEMPTS_PER_MINUTE", "20")
	t.Setenv("TEMPORARY_PASSWORD_ISSUE_PROJECT_ATTEMPTS_PER_MINUTE", "200")
	t.Setenv("TEMPORARY_PASSWORD_SETUP_PROJECT_ATTEMPTS_PER_MINUTE", "300")
	var cfg passwordservice.TemporaryPasswordConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil || cfg.Validate() != nil {
		t.Fatal("invalid parsed configuration", err)
	}
	if cfg.TTL != 2*time.Hour || cfg.SetupTTL != 5*time.Minute || cfg.ReissueCooldown != 2*time.Minute || cfg.IssueActorAttemptsPerMinute != 20 || cfg.IssueProjectAttemptsPerMinute != 200 || cfg.SetupProjectAttemptsPerMinute != 300 {
		t.Fatal("env values ignored")
	}
	for _, mutate := range []func(*passwordservice.TemporaryPasswordConfig){
		func(c *passwordservice.TemporaryPasswordConfig) { c.TTL = 0 },
		func(c *passwordservice.TemporaryPasswordConfig) { c.SetupTTL = c.TTL + time.Second },
		func(c *passwordservice.TemporaryPasswordConfig) { c.ReissueCooldown = 0 },
		func(c *passwordservice.TemporaryPasswordConfig) { c.IssueActorAttemptsPerMinute = 0 },
		func(c *passwordservice.TemporaryPasswordConfig) { c.IssueProjectAttemptsPerMinute = 0 },
		func(c *passwordservice.TemporaryPasswordConfig) { c.SetupProjectAttemptsPerMinute = 0 },
	} {
		bad := cfg
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid budget accepted")
		}
	}
	if (passwordservice.TemporaryPasswordConfig{}).Validate() != nil {
		t.Fatal("disabled profile requires settings")
	}
}

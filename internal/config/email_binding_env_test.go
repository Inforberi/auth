package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func TestEmailBindingConfiguration(t *testing.T) {
	t.Setenv("EMAIL_BINDING_ENABLED", "true")
	t.Setenv("EMAIL_BINDING_TTL", "3m")
	t.Setenv("EMAIL_BINDING_REQUESTS_PER_MINUTE", "300")
	t.Setenv("EMAIL_BINDING_CONFIRMATIONS_PER_MINUTE", "2000")
	var cfg accountservice.EmailBindingConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil || cfg.Validate() != nil {
		t.Fatal(err, cfg)
	}
	if !cfg.Enabled || cfg.TTL != 3*time.Minute || cfg.RequestsPerMinute != 300 || cfg.ConfirmationsPerMinute != 2000 {
		t.Fatal(cfg)
	}
	for _, mutate := range []func(*accountservice.EmailBindingConfig){
		func(c *accountservice.EmailBindingConfig) { c.TTL = time.Second },
		func(c *accountservice.EmailBindingConfig) { c.TTL = 6 * time.Minute },
		func(c *accountservice.EmailBindingConfig) { c.RequestsPerMinute = 0 },
		func(c *accountservice.EmailBindingConfig) { c.ConfirmationsPerMinute = 0 },
	} {
		bad := cfg
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid binding config accepted", bad)
		}
	}
	c := validConfig()
	c.EmailBinding = cfg
	if c.Validate() == nil {
		t.Fatal("binding enabled without required MFA/email reauthentication")
	}
	if (accountservice.EmailBindingConfig{}).Validate() != nil {
		t.Fatal("disabled binding requires settings")
	}
}

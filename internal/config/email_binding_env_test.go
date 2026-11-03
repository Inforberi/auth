package config

import (
	"testing"
	"time"

	"github.com/ilyakaznacheev/cleanenv"

	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
)

func TestEmailBindingConfiguration(t *testing.T) {
	t.Setenv("EMAIL_BINDING_ENABLED", "true")
	t.Setenv("EMAIL_BINDING_TTL", "3m")
	t.Setenv("EMAIL_BINDING_REQUESTS_PER_MINUTE", "300")
	t.Setenv("EMAIL_BINDING_CONFIRMATIONS_PER_MINUTE", "2000")
	var cfg accountemail.EmailBindingConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil || cfg.Validate() != nil {
		t.Fatal(err, cfg)
	}
	if !cfg.Enabled || cfg.TTL != 3*time.Minute || cfg.RequestsPerMinute != 300 || cfg.ConfirmationsPerMinute != 2000 {
		t.Fatal(cfg)
	}
	for _, mutate := range []func(*accountemail.EmailBindingConfig){
		func(c *accountemail.EmailBindingConfig) { c.TTL = time.Second },
		func(c *accountemail.EmailBindingConfig) { c.TTL = 6 * time.Minute },
		func(c *accountemail.EmailBindingConfig) { c.RequestsPerMinute = 0 },
		func(c *accountemail.EmailBindingConfig) { c.ConfirmationsPerMinute = 0 },
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
	if (accountemail.EmailBindingConfig{}).Validate() != nil {
		t.Fatal("disabled binding requires settings")
	}
}

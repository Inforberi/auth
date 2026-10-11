package config

import (
	"strings"
	"testing"

	"github.com/ilyakaznacheev/cleanenv"

	google "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
)

func TestGoogleConfiguration(t *testing.T) {
	if (google.Config{}).Validate() != nil {
		t.Fatal("disabled Google requires credentials")
	}
	t.Setenv("GOOGLE_LOGIN_ENABLED", "true")
	t.Setenv("GOOGLE_REGISTRATION_ENABLED", "true")
	t.Setenv("GOOGLE_OIDC_CLIENT_ID", "123-fixture.apps.googleusercontent.com")
	t.Setenv("GOOGLE_OIDC_CLIENT_SECRET", "fixture-secret")
	t.Setenv("GOOGLE_OIDC_REDIRECT_URI", "https://auth.example/api/v1/auth/google/callback")
	t.Setenv("GOOGLE_LOGIN_IP_ATTEMPTS_PER_MINUTE", "40")
	t.Setenv("GOOGLE_LOGIN_PROJECT_ATTEMPTS_PER_MINUTE", "2000")
	var cfg google.Config
	if err := cleanenv.ReadEnv(&cfg); err != nil || cfg.Validate() != nil {
		t.Fatal("Google config invalid", err)
	}
	if !cfg.Enabled || !cfg.RegistrationEnabled || cfg.IPLimit != 40 || cfg.GlobalLimit != 2000 {
		t.Fatal("Google env ignored")
	}
	if flow := cfg.FlowConfig(); flow.Issuer != "https://accounts.google.com" || !flow.Enabled || !flow.RegistrationEnabled || flow.IPLimit != 40 || flow.GlobalLimit != 2000 {
		t.Fatal("flow config lost profile")
	}
	for _, mutate := range []func(*google.Config){
		func(c *google.Config) { c.ClientID = "123" },
		func(c *google.Config) { c.ClientID = " " + c.ClientID },
		func(c *google.Config) { c.ClientSecret = "" },
		func(c *google.Config) { c.ClientSecret = strings.Repeat("s", 1025) },
		func(c *google.Config) { c.RedirectURI = "http://auth.example/api/v1/auth/google/callback" },
		func(c *google.Config) { c.RedirectURI = "https://user@auth.example/api/v1/auth/google/callback" },
		func(c *google.Config) { c.RedirectURI = "https://auth.example/api/v1/auth/telegram/callback" },
		func(c *google.Config) { c.RedirectURI += "?next=untrusted" },
		func(c *google.Config) { c.RedirectURI += "#fragment" },
		func(c *google.Config) { c.IPLimit = 0 },
		func(c *google.Config) { c.GlobalLimit = 0 },
	} {
		bad := cfg
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid Google configuration accepted")
		}
	}
}

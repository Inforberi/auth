package config

import (
	"testing"

	"github.com/ilyakaznacheev/cleanenv"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSettingsSourceEnvironment(t *testing.T) {
	for _, mode := range []string{"api", "env", "ENV", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("AUTH_SETTINGS_MODE", mode)
			t.Setenv("AUTH_PASSWORD_ENABLED", "true")
			t.Setenv("AUTH_REGISTRATION_ENABLED", "false")
			t.Setenv("AUTH_PASSWORD_EMAIL_VERIFICATION", "required")
			var source SettingsSourceConfig
			if err := cleanenv.ReadEnv(&source); err != nil {
				t.Fatal(err)
			}
			err := source.Validate()
			if mode != "api" && mode != "env" {
				if err == nil {
					t.Fatal("invalid mode accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cfg := Config{SettingsSource: source}
			policy := cfg.InitialAuthPolicy()
			if mode == "env" && (policy.Registration.Enabled || policy.PasswordEmailVerification != domain.VerificationRequired) {
				t.Fatal("ENV switches ignored")
			}
			if mode == "api" && (!policy.Registration.Enabled || policy.PasswordEmailVerification != domain.VerificationOptional) {
				t.Fatal("API compatibility changed")
			}
		})
	}
}

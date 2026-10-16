package config

import (
	"testing"
	"time"

	googleservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/google/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSavedPolicyAdapterReadiness(t *testing.T) {
	policy := settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationOptional}
	cfg := Config{}
	if err := cfg.ConfigureAuthAdapters(policy); err != nil || cfg.Google.Enabled || cfg.Telegram.Enabled {
		t.Fatal("disabled provider required secrets", err)
	}
	policy.Methods.Google = true
	if cfg.ConfigureAuthAdapters(policy) == nil {
		t.Fatal("enabled unconfigured provider")
	}
	cfg.Google = googleservice.Config{ClientID: "fixture.apps.googleusercontent.com", ClientSecret: "synthetic", RedirectURI: "https://auth.example/api/v1/auth/google/callback", IPLimit: 30, GlobalLimit: 1000}
	if err := cfg.ConfigureAuthAdapters(policy); err != nil || !cfg.Google.Enabled {
		t.Fatal("saved enable lost to ENV false", err)
	}
	policy.Methods.Google = false
	if err := cfg.ConfigureAuthAdapters(policy); err != nil || !cfg.Google.Enabled {
		t.Fatal("configured adapter cannot be reenabled", err)
	}
	policy.Methods.EmailOTP = true
	if cfg.ConfigureAuthAdapters(policy) == nil {
		t.Fatal("invalid OTP parameters admitted")
	}
	cfg.EmailOTP.TTL = 5 * time.Minute
	cfg.EmailOTP.ResendInterval = time.Minute
	cfg.EmailOTP.RequestGlobalLimit = 100
	cfg.EmailOTP.ConfirmGlobalLimit = 1000
	if err := cfg.ConfigureAuthAdapters(policy); err != nil || !cfg.EmailOTP.Enabled {
		t.Fatal(err)
	}
	if got := cfg.AvailableAuthMethods(); got != (settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true}) {
		t.Fatal("runtime availability confused with saved switches", got)
	}
}

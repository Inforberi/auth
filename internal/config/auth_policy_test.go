package config

import (
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestInitialAuthPolicy(t *testing.T) {
	var cfg Config
	p := cfg.InitialAuthPolicy()
	if !p.Methods.Password || !p.Registration.Enabled || p.Methods.Google || p.Methods.Telegram || p.Methods.EmailOTP || p.PasswordEmailVerification != domain.VerificationOptional {
		t.Fatal(p)
	}
	cfg.Google.Enabled = true
	cfg.Google.RegistrationEnabled = true
	cfg.Telegram.Enabled = true
	cfg.EmailOTP.Enabled = true
	p = cfg.InitialAuthPolicy()
	if !p.Methods.Google || !p.Methods.Telegram || !p.Methods.EmailOTP || !p.Registration.Google || p.Registration.Telegram {
		t.Fatal(p)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

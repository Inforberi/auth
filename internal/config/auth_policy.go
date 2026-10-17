package config

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

// InitialAuthPolicy is only a first-install seed, not an override of saved settings.
func (cfg Config) InitialAuthPolicy() domain.Policy {
	return domain.Policy{
		Methods:                   domain.PublicMethods{Password: true, EmailOTP: cfg.EmailOTP.Enabled, Google: cfg.Google.Enabled, Telegram: cfg.Telegram.Enabled},
		Registration:              domain.PublicRegistration{Enabled: true, Google: cfg.Google.RegistrationEnabled, Telegram: cfg.Telegram.RegistrationEnabled},
		PasswordEmailVerification: domain.VerificationOptional,
		TokenIssuance:             domain.TokenIssuance{SessionExchange: cfg.JWT.Enabled, Native: cfg.JWT.Enabled && cfg.JWT.NativeEnabled},
	}
}

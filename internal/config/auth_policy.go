package config

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

// InitialAuthPolicy supplies an API bootstrap seed or the explicitly ENV-owned policy.
func (cfg Config) InitialAuthPolicy() domain.Policy {
	policy := domain.Policy{
		Methods:                   domain.PublicMethods{Password: true, EmailOTP: cfg.EmailOTP.Enabled, Google: cfg.Google.Enabled, Telegram: cfg.Telegram.Enabled},
		Registration:              domain.PublicRegistration{Enabled: true, Google: cfg.Google.RegistrationEnabled, Telegram: cfg.Telegram.RegistrationEnabled},
		PasswordEmailVerification: domain.VerificationOptional,
		TokenIssuance:             domain.TokenIssuance{SessionExchange: cfg.JWT.Enabled, Native: cfg.JWT.Enabled && cfg.JWT.NativeEnabled},
	}
	if cfg.SettingsSource.Mode == domain.SourceENV {
		policy.Methods.Password = cfg.SettingsSource.PasswordEnabled
		policy.Registration.Enabled = cfg.SettingsSource.RegistrationEnabled
		policy.PasswordEmailVerification = cfg.SettingsSource.Verification
	}
	if cfg.SettingsSource.InstallClosedProfile && cfg.SettingsSource.Mode.Effective() == domain.SourceAPI {
		policy.Registration = domain.PublicRegistration{}
		policy.PasswordEmailVerification = domain.VerificationDisabled
	}
	return policy
}

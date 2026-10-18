package config

import (
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

// Deployment validation precedes opening SQL; saved provider switches are not available yet.
func (cfg Config) ValidateDeployment() error {
	if err := cfg.ValidatePlatform(); err != nil {
		return err
	}
	cfg.Google.Enabled = false
	cfg.Telegram.Enabled = false
	cfg.EmailOTP.Enabled = false
	return cfg.Validate()
}

// Adapter readiness covers callback/budgets; managed credential readiness is checked in settings SQL.
func (cfg *Config) ConfigureAuthAdapters(policy domain.Policy) error {
	google := cfg.Google
	google.Enabled = true
	googleErr := google.ValidateOperational()
	if policy.Methods.Google && googleErr != nil {
		return fmt.Errorf("saved Google policy: %w", googleErr)
	}
	cfg.Google.Enabled = googleErr == nil
	telegram := cfg.Telegram
	telegram.Enabled = true
	telegramErr := telegram.ValidateOperational()
	if policy.Methods.Telegram && telegramErr != nil {
		return fmt.Errorf("saved Telegram policy: %w", telegramErr)
	}
	cfg.Telegram.Enabled = telegramErr == nil
	otp := cfg.EmailOTP
	otp.Enabled = true
	otpErr := otp.Validate()
	if policy.Methods.EmailOTP && otpErr != nil {
		return fmt.Errorf("saved email OTP policy: %w", otpErr)
	}
	cfg.EmailOTP.Enabled = otpErr == nil
	return nil
}

// Called after ConfigureAuthAdapters; switches here describe constructed adapters, not public policy.
func (cfg Config) AvailableAuthMethods() domain.PublicMethods {
	return domain.PublicMethods{Password: true, EmailOTP: cfg.EmailOTP.Enabled, Google: cfg.Google.Enabled, Telegram: cfg.Telegram.Enabled}
}

package config

import (
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type SettingsSourceConfig struct {
	InstallClosedProfile       bool                     `env:"AUTH_INSTALL_CLOSED_PROFILE" env-default:"false"`
	ConfirmRetentionShortening bool                     `env:"AUTH_ENV_CONFIRM_RETENTION_SHORTENING" env-default:"false"`
	Mode                       domain.SourceMode        `env:"AUTH_SETTINGS_MODE" env-default:"api"`
	PasswordEnabled            bool                     `env:"AUTH_PASSWORD_ENABLED" env-default:"true"`
	RegistrationEnabled        bool                     `env:"AUTH_REGISTRATION_ENABLED" env-default:"true"`
	Verification               domain.EmailVerification `env:"AUTH_PASSWORD_EMAIL_VERIFICATION" env-default:"optional"`
}

func (c SettingsSourceConfig) Validate() error {
	if c.Mode.Validate() != nil {
		return fmt.Errorf("AUTH_SETTINGS_MODE must be api or env")
	}

	return nil
}

func (cfg Config) validateSettingsPool() error {
	if cfg.Postgres.MaxConns < 2 {
		return fmt.Errorf("MAX_CONNS must be at least 2: settings source reserves one connection from this pool")
	}
	return nil
}

package config

import "time"

type PasswordConfig struct {
	ResetTokenTTL time.Duration `env:"PASSWORD_RESET_TOKEN_TTL" env-required:"true"`
	ResetURL      string        `env:"PASSWORD_RESET_URL" env-required:"true"`
}

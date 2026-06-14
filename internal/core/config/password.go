package config

import "time"

type PasswordConfig struct {
	ResetTokenTTL time.Duration `env:"PASSWORD_RESET_TOKEN_TTL" env-required:"true"`
}

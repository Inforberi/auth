package service

import (
	"time"
)

type Config struct {
	ResetTokenTTL time.Duration `env:"PASSWORD_RESET_TOKEN_TTL" env-required:"true"`
	ResetURL      string        `env:"PASSWORD_RESET_URL" env-required:"true"`
}

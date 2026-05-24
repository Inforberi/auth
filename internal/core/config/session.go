package config

import "time"

type SessionConfig struct {
	SessionTTL time.Duration `env:"SESSION_TTL" env-default:"336h"`
}

package config

import "time"

type SessionConfig struct {
	SessionTTL              time.Duration `env:"SESSION_TTL" env-default:"168h"`
	AbsoluteSessionTTL      time.Duration `env:"SESSION_TTL" env-default:"336h"`
	SessionRefreshThreshold time.Duration `env:"SESSION_REFRESH_THRESHOLD" env-default:"24h"`
}

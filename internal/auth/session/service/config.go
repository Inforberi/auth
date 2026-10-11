package service

import (
	"time"
)

type Config struct {
	FreshAuthTTL            time.Duration `env:"SESSION_FRESH_AUTH_TTL" env-default:"5m"`
	SessionTTL              time.Duration `env:"SESSION_TTL" env-default:"168h"`
	AbsoluteSessionTTL      time.Duration `env:"ABSOLUTE_SESSION_TTL" env-default:"336h"`
	SessionRefreshThreshold time.Duration `env:"SESSION_REFRESH_THRESHOLD" env-default:"24h"`
}

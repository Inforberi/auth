package service

import (
	"fmt"
	"time"
)

type Config struct {
	FreshAuthTTL            time.Duration `env:"SESSION_FRESH_AUTH_TTL" env-default:"5m"`
	SessionTTL              time.Duration `env:"SESSION_TTL" env-default:"168h"`
	AbsoluteSessionTTL      time.Duration `env:"ABSOLUTE_SESSION_TTL" env-default:"336h"`
	SessionRefreshThreshold time.Duration `env:"SESSION_REFRESH_THRESHOLD" env-default:"24h"`
	AdminIdleTimeout        time.Duration `env:"ADMIN_SESSION_IDLE_TIMEOUT" env-default:"30m"`
	AdminAbsoluteTTL        time.Duration `env:"ADMIN_SESSION_ABSOLUTE_TTL" env-default:"12h"`
	AdminActivityInterval   time.Duration `env:"ADMIN_SESSION_ACTIVITY_INTERVAL" env-default:"1m"`
}

func (cfg Config) Validate() error {
	if cfg.FreshAuthTTL < time.Minute || cfg.FreshAuthTTL > 15*time.Minute {
		return fmt.Errorf("SESSION_FRESH_AUTH_TTL must be between 1m and 15m")
	}
	if cfg.SessionTTL <= 0 || cfg.AbsoluteSessionTTL < cfg.SessionTTL || cfg.SessionRefreshThreshold <= 0 || cfg.SessionRefreshThreshold >= cfg.SessionTTL {
		return fmt.Errorf("invalid session durations")
	}
	if cfg.AdminIdleTimeout < time.Minute || cfg.AdminAbsoluteTTL < cfg.AdminIdleTimeout ||
		cfg.AdminActivityInterval < time.Second || cfg.AdminActivityInterval > cfg.AdminIdleTimeout/10 ||
		cfg.AdminIdleTimeout%time.Second != 0 || cfg.AdminAbsoluteTTL%time.Second != 0 || cfg.AdminActivityInterval%time.Second != 0 {
		return fmt.Errorf("admin session durations must be whole seconds: idle >= 1m, absolute >= idle, activity interval 1s..idle/10")
	}
	return nil
}

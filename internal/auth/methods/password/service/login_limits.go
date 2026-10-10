package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type CapacityConfig struct {
	HashConcurrency  int `env:"PASSWORD_HASH_CONCURRENCY" env-default:"2"`
	LoginIPLimit     int `env:"LOGIN_IP_LIMIT" env-default:"30"`
	LoginEmailLimit  int `env:"LOGIN_EMAIL_LIMIT" env-default:"10"`
	LoginGlobalLimit int `env:"LOGIN_GLOBAL_LIMIT" env-default:"1000"`
}

func (c CapacityConfig) Validate() error {
	if c.HashConcurrency < 1 || c.HashConcurrency > 32 {
		return fmt.Errorf("PASSWORD_HASH_CONCURRENCY must be between 1 and 32")
	}
	if c.LoginIPLimit < 1 || c.LoginEmailLimit < 1 || c.LoginGlobalLimit < 1 {
		return fmt.Errorf("login limits must be positive")
	}
	return nil
}

type LoginLimit struct {
	limiter RecoveryLimiter
	cipher  loginDigester
	cfg     CapacityConfig
}

type loginDigester interface{ Digest(string) string }

func NewLoginLimit(limiter RecoveryLimiter, cipher loginDigester, cfg CapacityConfig) *LoginLimit {
	return &LoginLimit{limiter: limiter, cipher: cipher, cfg: cfg}
}

func (l *LoginLimit) Allow(ctx context.Context, email, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, budget := range []struct {
		key   string
		limit int
	}{
		{"login-ip:" + ip, l.cfg.LoginIPLimit},
		{"login-email:" + email, l.cfg.LoginEmailLimit},
		{"login-global", l.cfg.LoginGlobalLimit},
	} {
		allowed, err := l.limiter.Allow(ctx, l.cipher.Digest(budget.key), budget.limit, time.Minute)
		if err != nil {
			return fmt.Errorf("%w: %w", domain.ErrLoginUnavailable, err)
		}
		if !allowed {
			return domain.ErrLoginLimited
		}
	}
	return nil
}

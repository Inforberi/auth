package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func LimitAttempts(ctx context.Context, limiter RecoveryLimiter, digest func(string) string, key string, limit int, window time.Duration) error {
	allowed, err := limiter.Allow(ctx, digest(key), limit, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrRecoveryLimited
	}
	return nil
}

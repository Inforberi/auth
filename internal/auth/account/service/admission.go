package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func Admit(ctx context.Context, limiter Limiter, cipher Cipher, key string, maxRequests int, window time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	allowed, err := limiter.Allow(ctx, cipher.Digest(key), maxRequests, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrVerificationLimited
	}
	return nil
}

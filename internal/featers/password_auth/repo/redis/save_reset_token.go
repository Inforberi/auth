package password_redis

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

func (r *RedisRepo) SaveResetToken(ctx context.Context, tokenHash string, userID domain.UserID, ttl time.Duration) error {
	forgotKey := forgotPasswordTokenKey(tokenHash)
	userKey := forgotPasswordUserTokenKey(userID)

	oldHash, err := r.db.Get(ctx, userKey).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("get old reset token: %w", err)
	}

	pipe := r.db.TxPipeline()

	if oldHash != "" {
		pipe.Del(ctx, forgotPasswordTokenKey(oldHash))
	}

	pipe.Set(ctx, forgotKey, userID, ttl)
	pipe.Set(ctx, userKey, tokenHash, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("save forgot password token: %w", err)
	}

	return nil
}

package password_redis

import (
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	db *redis.Client
}

func forgotPasswordTokenKey(token string) string {
	return fmt.Sprintf("auth:password:reset:%s", token)
}

func forgotPasswordUserTokenKey(userId domain.UserID) string {
	return fmt.Sprintf("auth:password:reset:user:%s", userId)
}

func New(db *redis.Client) *RedisRepo {
	return &RedisRepo{db: db}
}

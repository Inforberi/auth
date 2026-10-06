package redis

import (
	"fmt"

	redis "github.com/redis/go-redis/v9"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type RedisRepo struct {
	db *redis.Client
}

func forgotPasswordTokenKey(token string) string {
	return fmt.Sprintf("auth:password:reset:%s", token)
}

func forgotPasswordUserTokenKey(userId accountmodel.UserID) string {
	return fmt.Sprintf("auth:password:reset:user:%s", userId)
}

func New(db *redis.Client) *RedisRepo {
	return &RedisRepo{db: db}
}

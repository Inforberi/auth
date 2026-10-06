package redis

import (
	"context"
	"fmt"
	"time"

	redis "github.com/redis/go-redis/v9"
)

func New(ctx context.Context, cfg Config) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:                  fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Password:              cfg.Password,
		DB:                    0,
		ContextTimeoutEnabled: true,

		PoolSize:     20,
		MinIdleConns: 5,

		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,

		MaxRetries:      3,
		MinRetryBackoff: 8 * time.Millisecond,
		MaxRetryBackoff: 512 * time.Millisecond,
	})
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := rdb.Ping(connectCtx).Err(); err != nil {
		if closeErr := rdb.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to connect and close Redis")
		}
		return nil, fmt.Errorf("failed to connect to Redis")
	}

	return rdb, nil
}

package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct{ db *redis.Client }

func New(db *redis.Client) *RedisRepo { return &RedisRepo{db: db} }
func (r *RedisRepo) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := r.db.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`, []string{"auth:password-recovery:limit:" + key}, window.Milliseconds()).Int64()
	return count <= int64(limit), err
}

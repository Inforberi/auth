package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

type RedisRepo struct {
	db     *redis.Client
	prefix string
}

func New(db *redis.Client) *RedisRepo {
	return &RedisRepo{db: db, prefix: "auth:password-recovery:limit:"}
}

func NewScoped(db *redis.Client, scope realmscope.Scope) (*RedisRepo, error) {
	prefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	if err != nil {
		return nil, err
	}
	return &RedisRepo{db: db, prefix: prefix}, nil
}

func (r *RedisRepo) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := r.db.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`, []string{r.prefix + key}, window.Milliseconds()).Int64()
	return err == nil && count <= int64(limit), err
}

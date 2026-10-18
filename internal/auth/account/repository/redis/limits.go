package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

type Limiter struct {
	client *redis.Client
	prefix string
}

func New(client *redis.Client) *Limiter {
	return &Limiter{client: client, prefix: "auth:email-verification:limit:"}
}

func NewScoped(client *redis.Client, scope realmscope.Scope) (*Limiter, error) {
	prefix, err := scope.RedisPrefix("email-verification-limit", "auth:email-verification:limit:")
	if err != nil {
		return nil, err
	}
	return &Limiter{client: client, prefix: prefix}, nil
}

const rateScript = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return count
`

func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := l.client.Eval(ctx, rateScript, []string{l.prefix + key}, window.Milliseconds()).Int64()
	return err == nil && count <= int64(limit), err
}

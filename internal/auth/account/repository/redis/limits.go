package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Limiter struct{ client *redis.Client }

func New(client *redis.Client) *Limiter { return &Limiter{client: client} }

const rateScript = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return count
`

func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := l.client.Eval(ctx, rateScript, []string{"auth:email-verification:limit:" + key}, window.Milliseconds()).Int64()
	return count <= int64(limit), err
}

package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type SMTPLimits struct{ client *redis.Client }

func NewSMTP(client *redis.Client) *SMTPLimits { return &SMTPLimits{client: client} }

func (l *SMTPLimits) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := l.client.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`,
		[]string{"auth:settings:smtp-test:" + key}, window.Milliseconds()).Int64()
	return count <= int64(limit), err
}

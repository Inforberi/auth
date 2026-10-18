package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

type SMTPLimits struct {
	client *redis.Client
	prefix string
}

func NewSMTP(client *redis.Client) *SMTPLimits {
	return &SMTPLimits{client: client, prefix: "auth:settings:smtp-test:"}
}

func NewSMTPScoped(client *redis.Client, scope realmscope.Scope) (*SMTPLimits, error) {
	prefix, err := scope.RedisPrefix("smtp-test-limit", "auth:settings:smtp-test:")
	if err != nil {
		return nil, err
	}
	return &SMTPLimits{client: client, prefix: prefix}, nil
}

func (l *SMTPLimits) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := l.client.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`,
		[]string{l.prefix + key}, window.Milliseconds()).Int64()
	return err == nil && count <= int64(limit), err
}

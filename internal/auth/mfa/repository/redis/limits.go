package redis

import (
	"context"
	"errors"
	"time"

	redis "github.com/redis/go-redis/v9"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/redislimit"
)

type Limiter struct {
	client *redis.Client
	prefix string
}

func New(client *redis.Client) *Limiter { return &Limiter{client: client, prefix: "auth:mfa:limit:"} }

func NewScoped(client *redis.Client, scope realmscope.Scope) (*Limiter, error) {
	prefix, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	if err != nil {
		return nil, err
	}
	return &Limiter{client: client, prefix: prefix}, nil
}

const limitScript = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return count
`

func (l *Limiter) Allow(ctx context.Context, key string, count int, window time.Duration) (bool, error) {
	current, err := l.client.Eval(ctx, limitScript, []string{l.prefix + key}, window.Milliseconds()).Int64()
	return err == nil && current <= int64(count), err
}

func (l *Limiter) AllowAll(ctx context.Context, budgets []mfaservice.Budget) (bool, error) {
	if len(budgets) == 0 || len(budgets) > 3 {
		return false, errors.New("invalid admission budgets")
	}
	shared := make([]redislimit.Budget, len(budgets))
	for i, budget := range budgets {
		shared[i] = redislimit.Budget{Key: budget.Key, Count: budget.Count}
	}
	return redislimit.AllowMinute(ctx, l.client, l.prefix, shared)
}

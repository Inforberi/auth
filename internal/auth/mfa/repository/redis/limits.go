package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
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

const admissionScript = `
for i,key in ipairs(KEYS) do
  local value=redis.call('GET',key)
  if value then
    local count=tonumber(value)
    if not count or (value~='0' and not string.match(value,'^[1-9]%d*$')) or redis.call('PTTL',key)<0 then
      return redis.error_reply('invalid MFA admission counter')
    end
    if count>=tonumber(ARGV[i]) then return 0 end
  end
end
for _,key in ipairs(KEYS) do
  local count=redis.call('INCR',key)
  if count==1 then redis.call('PEXPIRE',key,60000) end
end
return 1`

func (l *Limiter) AllowAll(ctx context.Context, budgets []service.Budget) (bool, error) {
	if len(budgets) == 0 || len(budgets) > 3 {
		return false, errors.New("invalid MFA admission budgets")
	}
	keys, counts := make([]string, len(budgets)), make([]any, len(budgets))
	for i, budget := range budgets {
		if budget.Key == "" || len(budget.Key) > 256 || budget.Count < 1 || uint64(budget.Count) > 1<<53-1 {
			return false, errors.New("invalid MFA admission budget")
		}
		keys[i], counts[i] = l.prefix+budget.Key, budget.Count
		for j := 0; j < i; j++ {
			if keys[j] == keys[i] {
				return false, errors.New("duplicate MFA admission budget")
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	allowed, err := l.client.Eval(ctx, admissionScript, keys, counts...).Int64()
	return allowed == 1, err
}

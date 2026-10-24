package redislimit

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type Budget struct {
	Key   string
	Count int
}

const minuteScript = `
for i,key in ipairs(KEYS) do
  local value=redis.call('GET',key)
  if value then
    local count=tonumber(value)
    if not count or (value~='0' and not string.match(value,'^[1-9]%d*$')) or redis.call('PTTL',key)<0 then
      return redis.error_reply('invalid admission counter')
    end
    if count>=tonumber(ARGV[i]) then return 0 end
  end
end
for _,key in ipairs(KEYS) do
  local count=redis.call('INCR',key)
  if count==1 then redis.call('PEXPIRE',key,60000) end
end
return 1`

// AllowMinute charges all counters or none. Rejections allocate no new keys.
func AllowMinute(ctx context.Context, client *redis.Client, prefix string, budgets []Budget) (bool, error) {
	if client == nil || prefix == "" || len(prefix) > 256 || len(budgets) == 0 || len(budgets) > 3 {
		return false, errors.New("invalid admission budgets")
	}
	keys, counts := make([]string, len(budgets)), make([]any, len(budgets))
	for i, budget := range budgets {
		if budget.Key == "" || len(budget.Key) > 256 || budget.Count < 1 || uint64(budget.Count) > 1<<53-1 {
			return false, errors.New("invalid admission budget")
		}
		keys[i], counts[i] = prefix+budget.Key, budget.Count
		for j := 0; j < i; j++ {
			if keys[j] == keys[i] {
				return false, errors.New("duplicate admission budget")
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	allowed, err := client.Eval(ctx, minuteScript, keys, counts...).Int64()
	return allowed == 1, err
}

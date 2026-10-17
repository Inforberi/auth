package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type Limits struct {
	ActorPerMinute   int
	SessionPerMinute int
	IPPerMinute      int
	ProjectPerMinute int
}

func DefaultLimits() Limits {
	return Limits{ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000}
}

type Digester interface{ Digest(string) string }

type Limiter struct {
	client *redis.Client
	digest Digester
	limits Limits
}

func New(client *redis.Client, digest Digester, limits Limits) (*Limiter, error) {
	if client == nil || digest == nil {
		return nil, authjwt.ErrConfiguration
	}
	for _, limit := range []int{limits.ActorPerMinute, limits.SessionPerMinute, limits.IPPerMinute, limits.ProjectPerMinute} {
		if limit < 1 || limit > 1_000_000 {
			return nil, authjwt.ErrConfiguration
		}
	}
	return &Limiter{client: client, digest: digest, limits: limits}, nil
}

const issuanceBudget = `
for i,key in ipairs(KEYS) do
  local value=redis.call('GET',key)
  if value and tonumber(value)>=tonumber(ARGV[i]) then return 0 end
end
for _,key in ipairs(KEYS) do
  local value=redis.call('INCR',key)
  if value==1 then redis.call('PEXPIRE',key,60000) end
end
return 1`

func (l *Limiter) Allow(ctx context.Context, input service.ExchangeInput) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	// One slot and one bounded script: rejected budgets do not allocate more keys or prolong TTLs.
	const prefix = "auth:{jwt-issuance}:"
	keys := []string{
		prefix + "actor:" + l.digest.Digest(string(input.Actor.UserID)),
		prefix + "session:" + l.digest.Digest(input.SessionID),
		prefix + "ip:" + l.digest.Digest(input.IP),
		prefix + "project",
	}
	allowed, err := l.client.Eval(ctx, issuanceBudget, keys, l.limits.ActorPerMinute,
		l.limits.SessionPerMinute, l.limits.IPPerMinute, l.limits.ProjectPerMinute).Int64()
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if allowed != 1 {
		return domain.ErrRateLimited
	}
	return nil
}

// AllowCredentialLookup bounds refresh and native MFA lookup before high-cardinality keys/SQL.
func (l *Limiter) AllowCredentialLookup(ctx context.Context, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	const prefix = "auth:{jwt-refresh-lookup}:"
	allowed, err := l.client.Eval(ctx, issuanceBudget, []string{prefix + "ip:" + l.digest.Digest(ip), prefix + "project"}, l.limits.IPPerMinute, l.limits.ProjectPerMinute).Int64()
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if allowed != 1 {
		return domain.ErrRateLimited
	}
	return nil
}

func (l *Limiter) AllowNative(ctx context.Context, user accountdomain.UserID, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	const prefix = "auth:{jwt-issuance}:"
	keys := []string{prefix + "actor:" + l.digest.Digest(string(user)), prefix + "ip:" + l.digest.Digest(ip), prefix + "project"}
	allowed, err := l.client.Eval(ctx, issuanceBudget, keys, l.limits.ActorPerMinute, l.limits.IPPerMinute, l.limits.ProjectPerMinute).Int64()
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if allowed != 1 {
		return domain.ErrRateLimited
	}
	return nil
}

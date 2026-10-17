package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
)

func (l *Limiter) AllowIntrospection(ctx context.Context, clientID string, consumerLimit, projectLimit int) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	// clientID comes from the fixed authenticated manifest, never untrusted token claims.
	prefix := "auth:{jwt-introspection}:"
	allowed, err := l.client.Eval(ctx, issuanceBudget, []string{prefix + "client:" + l.digest.Digest(clientID), prefix + "project"}, consumerLimit, projectLimit).Int64()
	if err != nil {
		return fmt.Errorf("%w: introspection budget", domain.ErrUnavailable)
	}
	if allowed != 1 {
		return domain.ErrRateLimited
	}
	return nil
}

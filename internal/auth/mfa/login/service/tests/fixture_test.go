package service_test

import (
	"context"
	"time"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type limitStub struct {
	calls   int
	allowed bool
	err     error
	keys    []string
	counts  []int
}

func (l *limitStub) Allow(_ context.Context, key string, count int, _ time.Duration) (bool, error) {
	l.calls++
	l.keys = append(l.keys, key)
	l.counts = append(l.counts, count)
	return l.allowed, l.err
}

func (l *limitStub) AllowAll(_ context.Context, budgets []mfaservice.Budget) (bool, error) {
	for _, budget := range budgets {
		l.calls++
		l.keys = append(l.keys, budget.Key)
		l.counts = append(l.counts, budget.Count)
	}
	return l.allowed, l.err
}

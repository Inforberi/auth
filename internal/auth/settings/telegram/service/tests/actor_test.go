package service_test

import (
	"context"
	"strings"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
)

var testActor = accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}

type botLimiter struct {
	allowed bool
	err     error
	calls   int
}

func (l *botLimiter) Allow(context.Context, string, int, time.Duration) (bool, error) {
	l.calls++
	return l.allowed, l.err
}

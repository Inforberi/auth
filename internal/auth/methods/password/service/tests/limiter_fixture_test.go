package service_test

import (
	"context"
	"time"
)

type recoveryLimit struct {
	allow bool
	err   error
}

func (l *recoveryLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return l.allow, l.err
}

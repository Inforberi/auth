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

type denyLogin struct{ err error }

func (l *denyLogin) Allow(context.Context, string, string) error { return l.err }

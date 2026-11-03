package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type limiter struct {
	allowed bool
	err     error
	keys    []string
}

func (l *limiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	return l.allowed, l.err
}

func provisionFixture(t *testing.T) (*limiter, *secretbox.Cipher) {
	t.Helper()
	c, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	return &limiter{allowed: true}, c
}

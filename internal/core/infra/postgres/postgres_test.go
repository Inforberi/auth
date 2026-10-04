package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCanceledStartupReturnsNoPoolOrCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	pool, err := New(ctx, Config{URL: "postgres://user:private-password@127.0.0.1:1/auth?sslmode=disable", MaxConns: 2})
	if pool != nil {
		pool.Close()
		t.Fatal("pool leaked after failed Ping")
	}
	if err == nil || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("unexpected startup error: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("canceled startup exceeded deadline")
	}
}

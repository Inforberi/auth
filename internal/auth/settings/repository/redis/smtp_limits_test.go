package redis

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestSMTPRedisLimits(t *testing.T) {
	addr := os.Getenv("AUTH_SMTP_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("dedicated localhost Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, DB: 15, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	if count, err := client.DBSize(t.Context()).Result(); err != nil || count != 0 {
		t.Fatal("disposable DB 15 must be empty", err)
	}
	limits := NewSMTP(client)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 32 {
		wg.Go(func() {
			allowed, err := limits.Allow(t.Context(), "synthetic-user", 3, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if allowed {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatal("non-atomic SMTP limit", accepted.Load())
	}
	ttl, err := client.TTL(t.Context(), "auth:settings:smtp-test:synthetic-user").Result()
	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatal(ttl, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := limits.Allow(t.Context(), "unavailable", 3, time.Minute); err == nil {
		t.Fatal("Redis error hidden")
	}
}

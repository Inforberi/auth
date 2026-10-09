package redis

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestLimiterRedis(t *testing.T) {
	addr := os.Getenv("AUTH_EMAIL_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("dedicated disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("fixture must use loopback")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	l := New(client)
	key := t.Name() + time.Now().Format("150405.000000000")
	var wg sync.WaitGroup
	results := make(chan bool, 30)
	errs := make(chan error, 30)
	for range 30 {
		wg.Go(func() { allowed, err := l.Allow(ctx, key, 5, time.Minute); results <- allowed; errs <- err })
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	accepted := 0
	for result := range results {
		if result {
			accepted++
		}
	}
	if accepted != 5 {
		t.Fatal("non-atomic limit", accepted)
	}
	ttl, err := client.PTTL(ctx, "auth:email-verification:limit:"+key).Result()
	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatal("missing TTL", ttl, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Allow(ctx, strings.Repeat("a", 64), 1, time.Minute); err == nil {
		t.Fatal("unavailable Redis accepted request")
	}
}

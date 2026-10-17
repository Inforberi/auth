package redis

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
)

func checkIntrospectionLimits(t *testing.T, client *redis.Client) {
	t.Helper()
	limiter, err := New(client, testDigester{}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			err := limiter.AllowIntrospection(t.Context(), "orders-api", 3, 5)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, domain.ErrRateLimited) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatal("non-atomic introspection cap", accepted.Load())
	}
	for _, key := range []string{"auth:{jwt-introspection}:project", "auth:{jwt-introspection}:client:" + testDigester{}.Digest("orders-api")} {
		if count, err := client.Get(t.Context(), key).Int(); err != nil || count != 3 {
			t.Fatal("partial increment", count, err)
		}
		if ttl, err := client.PTTL(t.Context(), key).Result(); err != nil || ttl <= 0 || ttl > time.Minute {
			t.Fatal("counter TTL", ttl, err)
		}
	}
	for range 2 {
		if err := limiter.AllowIntrospection(t.Context(), "other-api", 3, 5); err != nil {
			t.Fatal(err)
		}
	}
	before, err := client.DBSize(t.Context()).Result()
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.AllowIntrospection(t.Context(), "unallocated-api", 3, 5); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatal("project cap bypass", err)
	}
	if after, err := client.DBSize(t.Context()).Result(); err != nil || after != before {
		t.Fatal("rejection allocated keys", err)
	}
}

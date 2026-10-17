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

func checkRefreshLookupLimits(t *testing.T, client *redis.Client) {
	t.Helper()
	limiter, err := New(client, testDigester{}, Limits{ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 3, ProjectPerMinute: 4})
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			err := limiter.AllowCredentialLookup(t.Context(), "192.0.2.90")
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, domain.ErrRateLimited) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatal("non-atomic prelookup IP limit", accepted.Load())
	}
	const prefix = "auth:{jwt-refresh-lookup}:"
	for _, key := range []string{prefix + "project", prefix + "ip:" + testDigester{}.Digest("192.0.2.90")} {
		count, err := client.Get(t.Context(), key).Int()
		if err != nil || count != 3 {
			t.Fatal("partial prelookup budget", count, err)
		}
		ttl, err := client.PTTL(t.Context(), key).Result()
		if err != nil || ttl <= 0 || ttl > time.Minute {
			t.Fatal("unbounded prelookup TTL", ttl, err)
		}
	}
	if err := limiter.AllowCredentialLookup(t.Context(), "192.0.2.91"); err != nil {
		t.Fatal(err)
	}
	before, err := client.DBSize(t.Context()).Result()
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.AllowCredentialLookup(t.Context(), "192.0.2.92"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatal("project budget bypass", err)
	}
	after, err := client.DBSize(t.Context()).Result()
	if err != nil || after != before {
		t.Fatal("denial allocated more keys", err)
	}
}

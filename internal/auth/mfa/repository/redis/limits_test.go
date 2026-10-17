package redis

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestRedisMFALimits(t *testing.T) {
	addr := os.Getenv("AUTH_MFA_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("dedicated localhost Redis required")
	}
	db := redis.NewClient(&redis.Options{Addr: addr, DB: 15, MaxRetries: -1})
	defer func() { _ = db.Close() }()
	if count, err := db.DBSize(t.Context()).Result(); err != nil || count != 0 {
		t.Fatal("disposable DB 15 must be empty", err)
	}
	limiter := New(db)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for range 32 {
		wg.Go(func() {
			allowed, err := limiter.Allow(t.Context(), "mfa-test-pair", 5, time.Minute)
			if err != nil {
				t.Error(err)
			}
			if allowed {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 5 {
		t.Fatal("non-atomic MFA limit", accepted.Load())
	}
	ttl, err := db.TTL(t.Context(), "auth:mfa:limit:mfa-test-pair").Result()
	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatal("MFA counter TTL", ttl, err)
	}
	if allowed, err := limiter.Allow(t.Context(), "mfa-test-other-browser", 5, time.Minute); err != nil || !allowed {
		t.Fatal("other binding shares budget", err)
	}
	t.Run("atomic admission", func(t *testing.T) { checkAtomicAdmission(t, db, limiter) })
	t.Run("random token flood", func(t *testing.T) { checkMFAFlood(t, db, limiter) })
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Allow(t.Context(), "unavailable", 5, time.Minute); err == nil {
		t.Fatal("Redis error ignored")
	}
	if allowed, err := limiter.AllowAll(t.Context(), []service.Budget{{Key: "unavailable", Count: 5}}); err == nil || allowed {
		t.Fatal("Redis batch failure opened admission")
	}
}

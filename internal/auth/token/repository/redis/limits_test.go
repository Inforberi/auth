package redis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

type testDigester struct{}

func (testDigester) Digest(value string) string {
	h := hmac.New(sha256.New, []byte("synthetic fixture key"))
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

func TestRedisIssuanceLimits(t *testing.T) {
	addr := os.Getenv("AUTH_JWT_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("dedicated localhost Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, DB: 15, MaxRetries: -1, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	if count, err := client.DBSize(t.Context()).Result(); err != nil || count != 0 {
		t.Fatal("disposable DB 15 must be empty", err)
	}
	limiter, err := New(client, testDigester{}, Limits{ActorPerMinute: 10, SessionPerMinute: 3, IPPerMinute: 10, ProjectPerMinute: 10})
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			input := service.ExchangeInput{SessionID: "synthetic-session", IP: "192.0.2.1"}
			input.Actor.UserID = "synthetic-user"
			err := limiter.Allow(t.Context(), input)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, domain.ErrRateLimited) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 3 {
		t.Fatal("non-atomic session budget", accepted.Load())
	}
	const prefix = "auth:{jwt-issuance}:"
	for _, key := range []string{prefix + "project", prefix + "actor:" + testDigester{}.Digest("synthetic-user"), prefix + "session:" + testDigester{}.Digest("synthetic-session"), prefix + "ip:" + testDigester{}.Digest("192.0.2.1")} {
		count, err := client.Get(t.Context(), key).Int()
		if err != nil || count != 3 {
			t.Fatal("partial budget increment", count, err)
		}
		ttl, err := client.PTTL(t.Context(), key).Result()
		if err != nil || ttl <= 0 || ttl > time.Minute {
			t.Fatal("unbounded counter TTL", ttl, err)
		}
	}
	for i := range 7 {
		input := service.ExchangeInput{SessionID: "other-session-" + strconv.Itoa(i), IP: "192.0.2.2"}
		input.Actor.UserID = "other-user"
		if err := limiter.Allow(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	count, err := client.DBSize(t.Context()).Result()
	if err != nil {
		t.Fatal(err)
	}
	input := service.ExchangeInput{SessionID: "unallocated-session", IP: "192.0.2.3"}
	input.Actor.UserID = "unallocated-user"
	if err := limiter.Allow(t.Context(), input); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatal("project cap bypass", err)
	}
	if after, err := client.DBSize(t.Context()).Result(); err != nil || after != count {
		t.Fatal("rejection allocated keys", err)
	}
	for _, budget := range []string{"actor", "ip"} {
		t.Run(budget, func(t *testing.T) {
			limits := Limits{ActorPerMinute: 100, SessionPerMinute: 100, IPPerMinute: 100, ProjectPerMinute: 1000}
			if budget == "actor" {
				limits.ActorPerMinute = 1
			} else {
				limits.IPPerMinute = 1
			}
			limiter, err := New(client, testDigester{}, limits)
			if err != nil {
				t.Fatal(err)
			}
			first := service.ExchangeInput{SessionID: budget + "-session", IP: budget + "-ip"}
			first.Actor.UserID = accountdomain.UserID("budget-" + first.SessionID)
			if err := limiter.Allow(t.Context(), first); err != nil {
				t.Fatal(err)
			}
			second := first
			second.SessionID += "-different"
			if budget == "actor" {
				second.IP += "-different"
			} else {
				second.Actor.UserID += "-different"
			}
			if err := limiter.Allow(t.Context(), second); !errors.Is(err, domain.ErrRateLimited) {
				t.Fatal("budget bypass across sessions", budget, err)
			}
		})
	}
	checkRefreshLookupLimits(t, client)
	checkNativeIssuanceLimits(t, client)
	checkIntrospectionLimits(t, client)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow(t.Context(), input); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("Redis error allowed issuance", err)
	}
	if err := limiter.AllowCredentialLookup(t.Context(), input.IP); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("Redis error allowed refresh lookup", err)
	}
	if err := limiter.AllowNative(t.Context(), input.Actor.UserID, input.IP); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("Redis error allowed native issuance", err)
	}
	if err := limiter.AllowIntrospection(t.Context(), "orders-api", 100, 100); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("Redis failure allowed introspection", err)
	}
}

func TestRedisIssuanceConfiguration(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	defer func() { _ = client.Close() }()
	for _, limits := range []Limits{{}, {ActorPerMinute: -1, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000}, {ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 1_000_001}} {
		if _, err := New(client, testDigester{}, limits); err == nil {
			t.Fatal("invalid limits accepted")
		}
	}
	if _, err := New(nil, testDigester{}, DefaultLimits()); err == nil {
		t.Fatal("nil client accepted")
	}
}

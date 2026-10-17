package redis

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/service"
)

func checkNativeIssuanceLimits(t *testing.T, client *redis.Client) {
	t.Helper()
	limiter, err := New(client, testDigester{}, Limits{ActorPerMinute: 5, SessionPerMinute: 1, IPPerMinute: 20, ProjectPerMinute: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			err := limiter.AllowNative(t.Context(), "native-fixture-user", "192.0.2.77")
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, domain.ErrRateLimited) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 5 {
		t.Fatal("native budget became shared empty-session cap", accepted.Load())
	}
	const prefix = "auth:{jwt-issuance}:"
	if count, err := client.Exists(t.Context(), prefix+"session:"+testDigester{}.Digest("")).Result(); err != nil || count != 0 {
		t.Fatal("empty family key allocated", err)
	}
	input := service.ExchangeInput{SessionID: "native-exchange-fixture", IP: "192.0.2.78"}
	input.Actor.UserID = "native-fixture-user"
	if err := limiter.Allow(t.Context(), input); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatal("actor cap not shared with exchange", err)
	}
}

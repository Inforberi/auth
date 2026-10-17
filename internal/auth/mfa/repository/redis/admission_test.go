package redis

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkAtomicAdmission(t *testing.T, db *redis.Client, limiter *Limiter) {
	for exhausted := range 3 {
		budgets := []service.Budget{{Key: fmt.Sprintf("batch-%d-subject", exhausted), Count: 5}, {Key: fmt.Sprintf("batch-%d-ip", exhausted), Count: 10}, {Key: fmt.Sprintf("batch-%d-project", exhausted), Count: 50}}
		key := "auth:mfa:limit:" + budgets[exhausted].Key
		if err := db.Set(t.Context(), key, budgets[exhausted].Count, 45*time.Second).Err(); err != nil {
			t.Fatal(err)
		}
		before, err := db.DBSize(t.Context()).Result()
		if err != nil {
			t.Fatal(err)
		}
		for range 10 {
			allowed, err := limiter.AllowAll(t.Context(), budgets)
			if err != nil || allowed {
				t.Fatal("exhausted admission passed", err)
			}
		}
		after, err := db.DBSize(t.Context()).Result()
		if err != nil || after != before {
			t.Fatal("denied admission allocated keys", before, after, err)
		}
		count, err := db.Get(t.Context(), key).Int()
		if err != nil || count != budgets[exhausted].Count {
			t.Fatal("denied admission consumed budget", count, err)
		}
		ttl, err := db.PTTL(t.Context(), key).Result()
		if err != nil || ttl <= 0 || ttl > 45*time.Second {
			t.Fatal("denied admission extended TTL", ttl, err)
		}
	}
	other := redis.NewClient(db.Options())
	defer func() { _ = other.Close() }()
	replica := New(other)
	before, err := db.DBSize(t.Context()).Result()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i := range 64 {
		wg.Go(func() {
			worker := limiter
			if i%2 == 1 {
				worker = replica
			}
			allowed, err := worker.AllowAll(t.Context(), []service.Budget{{Key: fmt.Sprintf("concurrent-subject-%d", i), Count: 5}, {Key: "concurrent-ip", Count: 6}, {Key: "concurrent-project", Count: 10}})
			if err != nil {
				t.Error(err)
			}
			if allowed {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	after, err := db.DBSize(t.Context()).Result()
	if err != nil || accepted.Load() != 6 || after-before != 8 {
		t.Fatal("non-atomic shared admission", accepted.Load(), after-before, err)
	}
	for _, key := range []string{"concurrent-ip", "concurrent-project"} {
		value, err := db.Get(t.Context(), "auth:mfa:limit:"+key).Int()
		if err != nil || value != 6 {
			t.Fatal("partial budget accounting", value, err)
		}
	}
	if allowed, err := limiter.Allow(t.Context(), "legacy-admission", 2, time.Minute); err != nil || !allowed {
		t.Fatal(err)
	}
	legacy := []service.Budget{{Key: "legacy-admission", Count: 2}, {Key: "legacy-project", Count: 10}}
	if allowed, err := limiter.AllowAll(t.Context(), legacy); err != nil || !allowed {
		t.Fatal("legacy counter lost", err)
	}
	if allowed, err := limiter.AllowAll(t.Context(), legacy); err != nil || allowed {
		t.Fatal("legacy counter reset", err)
	}
	count, err := db.Get(t.Context(), "auth:mfa:limit:legacy-project").Int()
	if err != nil || count != 1 {
		t.Fatal("shared legacy refusal spent another counter", err)
	}
	for i, value := range []string{"1.5", "01", "not-a-counter"} {
		key := fmt.Sprintf("malformed-%d", i)
		if err := db.Set(t.Context(), "auth:mfa:limit:"+key, value, time.Minute).Err(); err != nil {
			t.Fatal(err)
		}
		before, err := db.DBSize(t.Context()).Result()
		if err != nil {
			t.Fatal(err)
		}
		allowed, err := limiter.AllowAll(t.Context(), []service.Budget{{Key: key + "-first", Count: 5}, {Key: key, Count: 5}})
		if err == nil || allowed {
			t.Fatal("malformed counter accepted")
		}
		after, err := db.DBSize(t.Context()).Result()
		if err != nil || before != after {
			t.Fatal("malformed counter caused partial write", err)
		}
	}
	if err := db.Set(t.Context(), "auth:mfa:limit:fixed-window", 1, 20*time.Second).Err(); err != nil {
		t.Fatal(err)
	}
	if allowed, err := limiter.AllowAll(t.Context(), []service.Budget{{Key: "fixed-window", Count: 2}}); err != nil || !allowed {
		t.Fatal(err)
	}
	ttl, err := db.PTTL(t.Context(), "auth:mfa:limit:fixed-window").Result()
	if err != nil || ttl <= 0 || ttl > 20*time.Second {
		t.Fatal("accepted batch prolonged existing window", ttl, err)
	}
}

type lookupProbe struct {
	service.LoginRepository
	calls atomic.Int32
}

func (p *lookupProbe) FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error) {
	p.calls.Add(1)
	return "", domain.ErrInvalidCode
}

func checkMFAFlood(t *testing.T, db *redis.Client, limiter *Limiter) {
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "mfa:v1")
	if err != nil {
		t.Fatal(err)
	}
	probe := &lookupProbe{}
	login, err := service.NewLogin(probe, cipher, totp.Authenticator{}, limiter, tokengenerate.New(), service.LoginConfig{ChallengeTTL: 5 * time.Minute, SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, UserLimitPerMinute: 5, IPLimitPerMinute: 10, GlobalLimitPerMinute: 50})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(t.Context(), "auth:mfa:limit:project", 50, time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	before, err := db.DBSize(t.Context()).Result()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 256 {
		wg.Go(func() {
			token, err := tokengenerate.New().GenerateToken()
			if err != nil {
				t.Error(err)
				return
			}
			_, err = login.Complete(t.Context(), service.CompleteLoginInput{Token: token, Binding: token, Code: "123456", IP: fmt.Sprintf("192.0.2.%d", i)})
			if !errors.Is(err, domain.ErrLimited) {
				t.Error("project flood reached owner lookup", err)
			}
		})
	}
	wg.Wait()
	after, err := db.DBSize(t.Context()).Result()
	if err != nil || before != after || probe.calls.Load() != 0 {
		t.Fatal("random-token flood allocated keys or reached SQL", before, after, probe.calls.Load(), err)
	}
}

func TestInvalidMFABatchBeforeRedis(t *testing.T) {
	for _, budgets := range [][]service.Budget{
		nil,
		{{Key: "", Count: 1}},
		{{Key: "valid", Count: 0}},
		{{Key: "duplicate", Count: 1}, {Key: "duplicate", Count: 2}},
		{{Key: "1", Count: 1}, {Key: "2", Count: 1}, {Key: "3", Count: 1}, {Key: "4", Count: 1}},
	} {
		if allowed, err := New(nil).AllowAll(t.Context(), budgets); err == nil || allowed {
			t.Fatal("invalid batch reached Redis")
		}
	}
}

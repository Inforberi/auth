package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type loginBudgetStub struct {
	keys   []string
	limits []int
	denyAt int
	err    error
}

func (l *loginBudgetStub) Allow(ctx context.Context, key string, max int, window time.Duration) (bool, error) {
	if _, ok := ctx.Deadline(); !ok || window != time.Minute {
		return false, errors.New("unbounded limiter")
	}
	l.keys = append(l.keys, key)
	l.limits = append(l.limits, max)
	return len(l.keys) != l.denyAt, l.err
}

func TestLoginLimits(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		deny       int
		dependency error
		want       error
		calls      int
	}{
		{0, nil, nil, 3},
		{1, nil, domain.ErrLoginLimited, 1},
		{2, nil, domain.ErrLoginLimited, 2},
		{3, nil, domain.ErrLoginLimited, 3},
		{0, errors.New("redis unavailable"), domain.ErrLoginUnavailable, 1},
	} {
		limiter := &loginBudgetStub{denyAt: tc.deny, err: tc.dependency}
		limit := NewLoginLimit(limiter, cipher, CapacityConfig{LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 1000})
		if err := limit.Allow(t.Context(), "user@example.com", "192.0.2.1"); !errors.Is(err, tc.want) {
			t.Fatal(err)
		}
		if len(limiter.keys) != tc.calls {
			t.Fatal("budget order", limiter.keys)
		}
		for _, key := range limiter.keys {
			if len(key) != 64 || strings.Contains(key, "user@") {
				t.Fatal("PII in Redis key", key)
			}
		}
	}
}

type denyLogin struct{ err error }

func (l denyLogin) Allow(context.Context, string, string) error { return l.err }

func TestLoginLimitBeforeSQLAndHash(t *testing.T) {
	service := New(nil, nil, nil, denyLogin{domain.ErrLoginLimited})
	if _, err := service.Login(t.Context(), LoginInput{Email: "user@example.com", Password: "ExamplePass1", IP: "192.0.2.1"}); !errors.Is(err, domain.ErrLoginLimited) {
		t.Fatal(err)
	}
	if _, err := service.LoginAdministrator(t.Context(), LoginInput{Email: "user@example.com", Password: "ExamplePass1", IP: "192.0.2.1"}); !errors.Is(err, domain.ErrLoginLimited) {
		t.Fatal("administrative limit bypass", err)
	}
}

func TestMissingLoginLimiterFailsClosed(t *testing.T) {
	service := New(nil, nil, nil, nil)
	if _, err := service.Login(t.Context(), LoginInput{Email: "user@example.com", Password: "ExamplePass1"}); !errors.Is(err, domain.ErrLoginUnavailable) {
		t.Fatal(err)
	}
}

func TestReauthenticationLimitsShareIPAndProjectBudgets(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	budget := &loginBudgetStub{}
	l := NewLoginLimit(budget, cipher, CapacityConfig{LoginIPLimit: 30, LoginEmailLimit: 10, LoginGlobalLimit: 1000})
	if err := l.AllowUser(t.Context(), "user", "ip"); err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"login-ip:ip", "reauth-user:user", "login-global"} {
		if budget.keys[i] != cipher.Digest(key) {
			t.Fatal("wrong budget scope", budget.keys)
		}
	}
}

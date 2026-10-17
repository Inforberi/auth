package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type exchangeRepo struct {
	proof SessionProof
	err   error
	calls int
	input ExchangeInput
	mode  string
}

func (r *exchangeRepo) Exchange(ctx context.Context, input ExchangeInput, mode string, sign func(context.Context, SessionProof) (*signing.SignedToken, error)) (*signing.SignedToken, error) {
	r.calls++
	r.input, r.mode = input, mode
	if r.err != nil {
		return nil, r.err
	}
	return sign(ctx, r.proof)
}

type exchangeSigner struct {
	claims authjwt.Claims
	now    time.Time
	err    error
}

func (s *exchangeSigner) Sign(_ context.Context, claims authjwt.Claims, now time.Time) (*signing.SignedToken, error) {
	s.claims, s.now = claims, now
	if s.err != nil {
		return nil, s.err
	}
	return &signing.SignedToken{Raw: "synthetic", ID: strings.Repeat("a", 43), ExpiresAt: time.Unix(claims.ExpiresAt, 0)}, nil
}

type exchangeLimiter struct {
	err   error
	calls int
}

func (l *exchangeLimiter) AllowRefreshLookup(_ context.Context, _ string) error { return l.err }

func (r *exchangeRepo) ResolveRefresh(_ context.Context, _ string) (RefreshBinding, error) {
	return RefreshBinding{}, domain.ErrInvalidRefresh
}

func (r *exchangeRepo) Refresh(_ context.Context, _ RefreshParams, _ func(context.Context, RefreshProof) (*ExchangeResult, error)) (*RefreshResult, error) {
	return nil, domain.ErrInvalidRefresh
}

func (l *exchangeLimiter) Allow(_ context.Context, _ ExchangeInput) error {
	l.calls++
	return l.err
}

func exchangeFixture(t *testing.T) (*Service, *exchangeRepo, *exchangeSigner, *exchangeLimiter, ExchangeInput) {
	t.Helper()
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	repo := &exchangeRepo{proof: SessionProof{AuthVersion: 7, Now: now, Deadline: now.Add(time.Hour), Method: "password", VerifiedAt: now.Add(-time.Hour)}}
	signer, limiter := &exchangeSigner{}, &exchangeLimiter{}
	svc, err := New(repo, signer, limiter, tokengenerate.New(), Config{AccessTTL: 2 * time.Minute, Resources: []Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}}}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	input := ExchangeInput{
		Actor:     accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)},
		SessionID: "22222222-2222-4222-8222-222222222222", Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.write", "orders.read"}, IP: "::ffff:192.0.2.1",
	}
	return svc, repo, signer, limiter, input
}

func TestExchangeClaims(t *testing.T) {
	svc, repo, signer, _, input := exchangeFixture(t)
	mfa := repo.proof.Now.Add(-time.Minute)
	repo.proof.MFAVerifiedAt = &mfa
	repo.proof.Deadline = repo.proof.Now.Add(35*time.Second + 500*time.Millisecond)
	result, err := svc.Exchange(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	c := signer.claims
	if c.Subject != string(input.Actor.UserID) || c.SessionID != input.SessionID || c.AuthVersion != 7 || c.Audience != "orders" || c.Mode != authjwt.Strict || c.Scope != "orders.read orders.write" ||
		c.ExpiresAt != repo.proof.Deadline.Unix() || c.AuthTime != repo.proof.VerifiedAt.Unix() || c.MFATime == nil || *c.MFATime != mfa.Unix() || !slices.Equal(c.Methods, []string{"pwd", "mfa"}) || !signer.now.Equal(repo.proof.Now) {
		t.Fatalf("wrong authoritative claims: %+v", c)
	}
	if result.Raw != "synthetic" || input.Scope[0] != "orders.write" || repo.input.IP != "192.0.2.1" || repo.mode != authjwt.Strict {
		t.Fatal("input/result changed", result, input)
	}
	for _, method := range []string{"password", "emailotp", "oidc"} {
		repo.proof.Method, repo.proof.MFAVerifiedAt = method, nil
		repo.proof.Deadline = repo.proof.Now.Add(time.Hour)
		if _, err := svc.Exchange(t.Context(), input); err != nil {
			t.Fatal(err)
		}
		if signer.claims.ExpiresAt != repo.proof.Now.Add(2*time.Minute).Unix() || signer.claims.MFATime != nil || len(signer.claims.Methods) != 1 {
			t.Fatal("TTL or assurance changed")
		}
	}
}

func TestExchangeAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ExchangeInput)
		want   error
	}{
		{"principal", func(i *ExchangeInput) { i.Actor.TokenHash = "bad" }, sessiondomain.ErrSessionNotFound},
		{"sid", func(i *ExchangeInput) { i.SessionID = "bad" }, sessiondomain.ErrSessionNotFound},
		{"IP", func(i *ExchangeInput) { i.IP = "untrusted" }, domain.ErrInvalidRequest},
		{"zone", func(i *ExchangeInput) { i.IP = "fe80::1%en0" }, domain.ErrInvalidRequest},
		{"audience", func(i *ExchangeInput) { i.Audience = "other" }, domain.ErrInvalidRequest},
		{"empty scope", func(i *ExchangeInput) { i.Scope = nil }, domain.ErrInvalidRequest},
		{"unknown permission", func(i *ExchangeInput) { i.Scope = []accessdomain.PermissionKey{"orders.admin"} }, domain.ErrForbidden},
		{"duplicate", func(i *ExchangeInput) { i.Scope = []accessdomain.PermissionKey{"orders.read", "orders.read"} }, domain.ErrForbidden},
		{"too many", func(i *ExchangeInput) { i.Scope = make([]accessdomain.PermissionKey, 65) }, domain.ErrInvalidRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, repo, _, limiter, input := exchangeFixture(t)
			test.mutate(&input)
			if result, err := svc.Exchange(t.Context(), input); !errors.Is(err, test.want) || result != nil || repo.calls != 0 || limiter.calls != 0 {
				t.Fatal(result, err, repo.calls, limiter.calls)
			}
		})
	}
	svc, repo, signer, limiter, input := exchangeFixture(t)
	limiter.err = domain.ErrUnavailable
	if result, err := svc.Exchange(t.Context(), input); !errors.Is(err, domain.ErrUnavailable) || result != nil || repo.calls != 0 {
		t.Fatal(result, err)
	}
	limiter.err = domain.ErrRateLimited
	if _, err := svc.Exchange(t.Context(), input); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatal(err)
	}
	limiter.err = nil
	repo.err = domain.ErrForbidden
	if result, err := svc.Exchange(t.Context(), input); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatal(result, err)
	}
	repo.err = nil
	signer.err = authjwt.ErrBusy
	if result, err := svc.Exchange(t.Context(), input); !errors.Is(err, authjwt.ErrBusy) || result != nil {
		t.Fatal(result, err)
	}
	for range cap(svc.admission) {
		svc.admission <- struct{}{}
	}
	before := limiter.calls
	if _, err := svc.Exchange(t.Context(), input); !errors.Is(err, authjwt.ErrBusy) || limiter.calls != before {
		t.Fatal("unbounded admission", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.Exchange(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestExchangeConfiguration(t *testing.T) {
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}})
	if err != nil {
		t.Fatal(err)
	}
	base := Config{AccessTTL: 2 * time.Minute, Resources: []Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read"}}}}
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"long TTL", func(c *Config) { c.AccessTTL = 6 * time.Minute }},
		{"zero TTL", func(c *Config) { c.AccessTTL = 0 }},
		{"fractional TTL", func(c *Config) { c.AccessTTL = time.Second + 1 }},
		{"empty", func(c *Config) { c.Resources = nil }},
		{"too many", func(c *Config) { c.Resources = make([]Resource, 33) }},
		{"bad audience", func(c *Config) { c.Resources[0].Audience = "a b" }},
		{"duplicate audience", func(c *Config) { c.Resources = append(c.Resources, c.Resources[0]) }},
		{"bad mode", func(c *Config) { c.Resources[0].Mode = "fallback" }},
		{"empty allowlist", func(c *Config) { c.Resources[0].Permissions = nil }},
		{"unknown permission", func(c *Config) { c.Resources[0].Permissions = []accessdomain.PermissionKey{"unknown.read"} }},
		{"duplicate permission", func(c *Config) {
			c.Resources[0].Permissions = []accessdomain.PermissionKey{"orders.read", "orders.read"}
		}},
		{"local core permission", func(c *Config) {
			c.Resources[0].Mode = authjwt.Local
			c.Resources[0].Permissions = []accessdomain.PermissionKey{settings.AuthSettingsManage}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			cfg.Resources = slices.Clone(base.Resources)
			test.mutate(&cfg)
			if _, err := resourcePolicies(cfg, catalog); !errors.Is(err, authjwt.ErrConfiguration) {
				t.Fatal(err)
			}
		})
	}
	if _, err := New(nil, &exchangeSigner{}, &exchangeLimiter{}, tokengenerate.New(), base, catalog); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal(err)
	}
	svc, err := New(&exchangeRepo{}, &exchangeSigner{}, &exchangeLimiter{}, tokengenerate.New(), base, catalog)
	if err != nil {
		t.Fatal(err)
	}
	base.Resources[0].Permissions[0] = "changed.permission"
	if !svc.resources["orders"].permissions["orders.read"] {
		t.Fatal("mutable configuration retained")
	}
	base.Resources[0].Permissions = []accessdomain.PermissionKey{"orders.read"}
	base.Resources[0].Mode = authjwt.Local
	policies, err := resourcePolicies(base, catalog)
	if err != nil || policies["orders"].mode != authjwt.Local {
		t.Fatal(err)
	}
}

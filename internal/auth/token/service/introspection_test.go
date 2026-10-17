package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type introspectionRepo struct {
	calls     int
	err       error
	requested []accessdomain.PermissionKey
}

func (r *introspectionRepo) Introspect(_ context.Context, _ authjwt.Claims, scope []accessdomain.PermissionKey) ([]accessdomain.PermissionKey, error) {
	r.calls++
	r.requested = scope
	return slices.Clone(scope), r.err
}

type introspectionBudget struct {
	calls int
	err   error
}

func (l *introspectionBudget) AllowIntrospection(context.Context, string, int, int) error {
	l.calls++
	return l.err
}

func introspectionFixture(t *testing.T) (*Introspection, *introspectionRepo, *introspectionBudget, string, func(string, string) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "current", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := authjwt.ParsePublicKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	hash := sha256.Sum256([]byte(secret))
	repo, budget := &introspectionRepo{}, &introspectionBudget{}
	cfg := IntrospectionConfig{Issuer: "https://auth.example", ConsumerPerMinute: 100, ProjectPerMinute: 100, Resources: []Resource{
		{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read"}},
		{Audience: "other", Permissions: []accessdomain.PermissionKey{"orders.read"}},
	}, Clients: []IntrospectionClientConfig{{ID: "orders-api", SecretHashes: []string{hex.EncodeToString(hash[:])}, Audiences: []string{"orders"}}}}
	svc, err := NewIntrospection(repo, budget, keys, cfg, catalog)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(audience, scope string) string {
		now := time.Now().Unix()
		claims := authjwt.Claims{Issuer: cfg.Issuer, Subject: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222", Audience: audience, IssuedAt: now, ExpiresAt: now + 120, ID: secret, AuthVersion: 1, Scope: scope, Mode: authjwt.Strict, AuthTime: now - 60, Methods: []string{"pwd"}}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "current"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		message, err := signer.Sign(data)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := message.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return svc, repo, budget, secret, sign
}

func TestIntrospectionAuthenticationAndAuthority(t *testing.T) {
	svc, repo, budget, secret, sign := introspectionFixture(t)
	for _, pair := range [][2]string{{"unknown", secret}, {"orders-api", secret + "x"}, {"orders-api", "wrong"}} {
		if client, ok := svc.Authenticate(pair[0], pair[1]); ok || client != nil {
			t.Fatal("invalid service authenticated")
		}
	}
	client, ok := svc.Authenticate("orders-api", secret)
	if !ok {
		t.Fatal("service rejected")
	}
	if _, err := svc.Inspect(t.Context(), &IntrospectionClient{id: "orders-api"}, "invalid"); !errors.Is(err, domain.ErrForbidden) || budget.calls != 0 {
		t.Fatal("forged capability accepted", err)
	}
	result, err := svc.Inspect(t.Context(), client, sign("orders", "orders.read orders.write"))
	if err != nil || !result.Active || result.Scope != "orders.read" || repo.calls != 1 || !slices.Equal(repo.requested, []accessdomain.PermissionKey{"orders.read"}) {
		t.Fatal("authority scope expansion", result, err)
	}
	if _, err := svc.Inspect(t.Context(), client, sign("other", "orders.read")); !errors.Is(err, domain.ErrForbidden) || repo.calls != 1 {
		t.Fatal("cross-audience SQL", err)
	}
	for _, raw := range []string{"invalid", sign("orders", "orders.write")} {
		if result, err := svc.Inspect(t.Context(), client, raw); err != nil || result.Active || repo.calls != 1 {
			t.Fatal("invalid token hit SQL", result, err)
		}
	}
	repo.err = authjwt.ErrInvalidToken
	if result, err := svc.Inspect(t.Context(), client, sign("orders", "orders.read")); err != nil || result.Active {
		t.Fatal("inactive authority exposed", err)
	}
	repo.err = errors.New("dependency")
	if _, err := svc.Inspect(t.Context(), client, sign("orders", "orders.read")); err == nil {
		t.Fatal("SQL fail open")
	}
	before := repo.calls
	budget.err = domain.ErrUnavailable
	if _, err := svc.Inspect(t.Context(), client, sign("orders", "orders.read")); !errors.Is(err, domain.ErrUnavailable) || repo.calls != before {
		t.Fatal("Redis fail open", err)
	}
	budget.err = nil
	svc.admission = make(chan struct{}, 1)
	svc.admission <- struct{}{}
	if _, err := svc.Inspect(t.Context(), client, "invalid"); !errors.Is(err, authjwt.ErrBusy) {
		t.Fatal("admission bypass", err)
	}
	<-svc.admission
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.Inspect(ctx, client, "invalid"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestIntrospectionClientValidationAndRotation(t *testing.T) {
	svc, _, _, oldSecret, _ := introspectionFixture(t)
	newSecret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	newHash := sha256.Sum256([]byte(newSecret))
	oldHash := sha256.Sum256([]byte(oldSecret))
	base := IntrospectionClientConfig{ID: "orders-api", SecretHashes: []string{hex.EncodeToString(oldHash[:]), hex.EncodeToString(newHash[:])}, Audiences: []string{"orders"}}
	clients, err := introspectionClients([]IntrospectionClientConfig{base}, svc.resources)
	if err != nil {
		t.Fatal(err)
	}
	svc.clients = clients
	for _, secret := range []string{oldSecret, newSecret} {
		if _, ok := svc.Authenticate(base.ID, secret); !ok {
			t.Fatal("rotation credential rejected")
		}
	}
	wrong := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	if client, ok := svc.Authenticate(base.ID, wrong); ok || client != nil {
		t.Fatal("wrong hash accepted")
	}
	for _, mutate := range []func(*IntrospectionClientConfig){
		func(c *IntrospectionClientConfig) { c.ID = "invalid id" },
		func(c *IntrospectionClientConfig) { c.SecretHashes = nil },
		func(c *IntrospectionClientConfig) { c.SecretHashes = []string{"bad"} },
		func(c *IntrospectionClientConfig) {
			c.SecretHashes = []string{base.SecretHashes[0], base.SecretHashes[0]}
		},
		func(c *IntrospectionClientConfig) {
			c.SecretHashes = []string{base.SecretHashes[0], base.SecretHashes[1], strings.Repeat("b", 64)}
		},
		func(c *IntrospectionClientConfig) { c.Audiences = nil },
		func(c *IntrospectionClientConfig) { c.Audiences = []string{"orders", "orders"} },
		func(c *IntrospectionClientConfig) { c.Audiences = []string{"unknown"} },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := introspectionClients([]IntrospectionClientConfig{cfg}, svc.resources); err == nil {
			t.Fatal("invalid client config accepted", cfg.ID)
		}
	}
	if _, err := introspectionClients([]IntrospectionClientConfig{base, base}, svc.resources); err == nil {
		t.Fatal("duplicate clients accepted")
	}
	clients, err = introspectionClients([]IntrospectionClientConfig{{ID: base.ID, SecretHashes: []string{base.SecretHashes[1]}, Audiences: base.Audiences}}, svc.resources)
	if err != nil {
		t.Fatal(err)
	}
	svc.clients = clients
	if _, ok := svc.Authenticate(base.ID, oldSecret); ok {
		t.Fatal("retired credential accepted")
	}
}

package router

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type consumerAuthorityRepository struct {
	revoked, unavailable atomic.Bool
	calls                atomic.Int32
}

func (r *consumerAuthorityRepository) Introspect(context.Context, authjwt.Claims, []accessdomain.PermissionKey) ([]accessdomain.PermissionKey, error) {
	r.calls.Add(1)
	if r.unavailable.Load() {
		return nil, errors.New("synthetic private dependency")
	}
	if r.revoked.Load() {
		return nil, authjwt.ErrInvalidToken
	}
	return []accessdomain.PermissionKey{"orders.read"}, nil
}

type consumerServiceBudget struct{}

func (consumerServiceBudget) AllowIntrospection(context.Context, string, int, int) error { return nil }

func TestConsumerWithAuthRouterOverTLS(t *testing.T) {
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
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.New("https://auth.example", "current", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), keys)
	if err != nil {
		t.Fatal(err)
	}
	secret := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	hash := sha256.Sum256([]byte(secret))
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	repo := &consumerAuthorityRepository{}
	online, err := tokenservice.NewIntrospection(repo, consumerServiceBudget{}, keys, tokenservice.IntrospectionConfig{
		Issuer: "https://auth.example", Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}},
		Clients: []tokenservice.IntrospectionClientConfig{{ID: "orders-api", SecretHashes: []string{hex.EncodeToString(hash[:])}, Audiences: []string{"orders"}}}, ConsumerPerMinute: 100, ProjectPerMinute: 100,
	}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	h := contractHandlers("prod")
	h.Config.JWT.Enabled = true
	h.Tokens = tokenhttp.New(&contractExchange{}, keys.JWKS(), zap.NewNop())
	h.Introspection = tokenhttp.NewIntrospection(online)
	server := httptest.NewTLSServer(New(h))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	consumer, err := authjwt.NewConsumer(t.Context(), authjwt.ConsumerConfig{
		Expected: authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict},
		JWKSURL:  server.URL + "/.well-known/jwks.json", IntrospectionURL: server.URL + "/api/v1/internal/auth/token/introspect", ClientID: "orders-api", ClientSecret: secret, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	now := time.Now()
	token, err := signer.Sign(t.Context(), authjwt.Claims{
		Subject: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222", Audience: "orders", ExpiresAt: now.Add(time.Minute).Unix(),
		AuthVersion: 1, Scope: "orders.read orders.write", Mode: authjwt.Strict, AuthTime: now.Add(-time.Minute).Unix(), Methods: []string{"pwd"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	read, err := authjwt.RequirePermissions("orders.read")
	if err != nil {
		t.Fatal(err)
	}
	handler := consumer.Middleware(read(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := authjwt.PrincipalFromContext(r.Context())
		if !ok || p.HasPermission("orders.write") {
			t.Error("effective grant escalation")
		}
		w.WriteHeader(204)
	})))
	request := func(want int) {
		t.Helper()
		r := httptest.NewRequest("GET", "https://orders.example/orders", nil)
		r.Header.Set("Authorization", "Bearer "+token.Raw)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	request(204)
	request(204)
	if repo.calls.Load() != 2 {
		t.Fatal("positive authority cached")
	}
	repo.revoked.Store(true)
	request(401)
	repo.revoked.Store(false)
	repo.unavailable.Store(true)
	request(503)
}

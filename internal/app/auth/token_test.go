package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestDisabledTokensDoNotOpenResources(t *testing.T) {
	owned := &resources{}
	handler, err := assembleTokens(context.Background(), nil, nil, settings.Config{PrivateKeyFile: "/not-readable", KeySetFile: "/not-readable", ResourceFile: "/not-readable"},
		accesssettings.Catalog{}, "", owned, zap.NewNop())
	if err != nil || handler != nil || len(owned.closers) != 0 {
		t.Fatal("disabled JWT opened resources", err)
	}
	if _, err := assembleTokens(context.Background(), nil, nil, settings.Config{Enabled: true}, accesssettings.Catalog{}, "", owned, zap.NewNop()); err == nil {
		t.Fatal("enabled invalid profile accepted")
	}
}

func TestTokenAssemblyRedis(t *testing.T) {
	addr := os.Getenv("AUTH_JWT_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("explicit disposable Redis not configured")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatal("dedicated localhost Redis required")
	}
	base := redis.NewClient(&redis.Options{Addr: addr, DB: 15, MaxRetries: 3})
	t.Cleanup(func() { _ = base.Close() })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "synthetic", Algorithm: "ES256", Use: "sig"}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privateFile, publicFile, resourceFile := filepath.Join(dir, "private.pem"), filepath.Join(dir, "jwks.json"), filepath.Join(dir, "resources.json")
	for path, data := range map[string][]byte{privateFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), publicFile: public, resourceFile: []byte(`{"resources":[{"audience":"orders","permissions":["orders.read"]}]}`)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "orders.read", Name: "Read orders"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := settings.Config{
		Enabled: true, Issuer: "https://auth.example", SigningKeyID: "synthetic", PrivateKeyFile: privateFile, KeySetFile: publicFile, ResourceFile: resourceFile,
		AccessTTL: 2 * time.Minute, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000,
	}
	owned := &resources{}
	t.Cleanup(owned.close)
	handler, err := assembleTokens(t.Context(), nil, base, cfg, catalog, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", owned, zap.NewNop())
	if err != nil || handler == nil || len(owned.closers) != 1 {
		t.Fatal("JWT assembly failed", err)
	}
	w := httptest.NewRecorder()
	handler.JWKS(w, httptest.NewRequest("GET", "https://auth.example/.well-known/jwks.json", nil))
	if _, err := authjwt.ParsePublicKeys(w.Body.Bytes()); err != nil {
		t.Fatal("non-public or malformed JWKS", err)
	}
	owned.close()
	owned.close()
	if err := base.Ping(t.Context()).Err(); err != nil {
		t.Fatal("JWT closed the shared Auth Redis client", err)
	}
	if base.Options().MaxRetries != 3 {
		t.Fatal("JWT modified shared retry policy")
	}
}

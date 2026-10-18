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
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestDisabledTokensDoNotOpenResources(t *testing.T) {
	owned := &resources{}
	handler, err := (realmSecurity{scope: realmscope.Legacy()}).assembleTokens(context.Background(), nil, nil, &config.Config{JWT: settings.Config{PrivateKeyFile: "/not-readable", KeySetFile: "/not-readable", ResourceFile: "/not-readable", IntrospectionClientFile: "/not-readable"}},
		nativeLoginDependencies{}, accesssettings.Catalog{}, "", owned, zap.NewNop())
	if err != nil || (handler.handler != nil || handler.service != nil || handler.native != nil || handler.introspection != nil) || len(owned.closers) != 0 {
		t.Fatal("disabled JWT opened resources", err)
	}
	if _, err := (realmSecurity{scope: realmscope.Legacy()}).assembleTokens(context.Background(), nil, nil, &config.Config{JWT: settings.Config{Enabled: true}}, nativeLoginDependencies{}, accesssettings.Catalog{}, "", owned, zap.NewNop()); err == nil {
		t.Fatal("enabled invalid profile accepted")
	}
}

func TestNativeTokenAssemblyRejectsDeploymentBeforeResources(t *testing.T) {
	base := config.Config{JWT: settings.Config{
		Enabled: true, NativeEnabled: true, Issuer: "https://auth.example", SigningKeyID: "synthetic",
		PrivateKeyFile: "/not-readable", KeySetFile: "/not-readable", ResourceFile: "/not-readable",
		AccessTTL: time.Minute, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000,
	}}
	for _, enabled := range []bool{false, true} {
		cfg := base
		cfg.JWT.Enabled = enabled
		want := "MFA_ENABLED"
		if !enabled {
			want = "JWT_ENABLED"
		}
		owned := &resources{}
		handler, err := (realmSecurity{scope: realmscope.Legacy()}).assembleTokens(t.Context(), nil, nil, &cfg, nativeLoginDependencies{}, accesssettings.Catalog{}, "", owned, zap.NewNop())
		if (handler.handler != nil || handler.service != nil || handler.native != nil) || err == nil || !strings.Contains(err.Error(), want) || len(owned.closers) != 0 {
			t.Fatal("invalid native deployment reached JWT files/Redis", handler, err)
		}
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
	clientFile := filepath.Join(dir, "clients.json")
	if err := os.WriteFile(clientFile, []byte(`{"clients":[{"id":"orders-api","secretHashes":["`+strings.Repeat("a", 64)+`"],"audiences":["orders"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.IntrospectionClientFile = clientFile
	cfg.IntrospectionConsumerPerMinute, cfg.IntrospectionProjectPerMinute = 60000, 60000
	cfg.NativeEnabled, cfg.RefreshIdleTTL, cfg.RefreshAbsoluteTTL, cfg.ProjectPerMinute = true, time.Hour, 2*time.Hour, 60
	deployment := &config.Config{
		JWT:       cfg,
		MFA:       mfaservice.Config{Enabled: true},
		Session:   sessionservice.Config{SessionTTL: time.Hour, AbsoluteSessionTTL: 2 * time.Hour, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute},
		Retention: accountservice.RetentionConfig{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180, BatchSize: 130, Interval: time.Minute},
	}
	owned := &resources{}
	t.Cleanup(owned.close)
	handler, err := (realmSecurity{scope: realmscope.Legacy()}).assembleTokens(t.Context(), nil, base, deployment, nativeLoginDependencies{password: &passwordservice.PasswordService{}, mfa: &mfaApp{login: &mfaservice.Login{}}, email: &emailOTPApp{}}, catalog, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", owned, zap.NewNop())
	if err != nil || handler.handler == nil || handler.native == nil || handler.introspection == nil || len(owned.closers) != 1 {
		t.Fatal("JWT assembly failed", err)
	}
	if !handler.deployment.Enabled || !handler.deployment.NativeEnabled || !handler.deployment.IntrospectionEnabled || handler.deployment.Resources[0].Mode != "strict" {
		t.Fatal("assembled deployment view", handler.deployment)
	}
	w := httptest.NewRecorder()
	handler.handler.JWKS(w, httptest.NewRequest("GET", "https://auth.example/.well-known/jwks.json", nil))
	if _, err := authjwt.ParsePublicKeys(w.Body.Bytes()); err != nil {
		t.Fatal("non-public or malformed JWKS", err)
	}
	// Construction only: runtime primary/MFA/SQL behavior is exercised by the disposable SQL suite.
	native, err := assembleNativeTokens(&handler, &passwordservice.PasswordService{}, &mfaApp{login: &mfaservice.Login{}}, &emailOTPApp{}, deployment, zap.NewNop())
	if err != nil || native == nil || len(owned.closers) != 1 {
		t.Fatal("native did not reuse token owner", err)
	}
	deployment.EmailOTP.Enabled = true
	if _, err := assembleNativeTokens(&handler, &passwordservice.PasswordService{}, &mfaApp{login: &mfaservice.Login{}}, &emailOTPApp{}, deployment, zap.NewNop()); err == nil {
		t.Fatal("native email enabled without adapter")
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

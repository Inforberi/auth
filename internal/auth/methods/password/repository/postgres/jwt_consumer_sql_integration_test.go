package postgres

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokendomain "github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type consumerSQLAuthority struct {
	*tokenpostgres.Repository
	calls atomic.Int32
}

func (r *consumerSQLAuthority) Introspect(ctx context.Context, claims authjwt.Claims, scope []accessdomain.PermissionKey) ([]accessdomain.PermissionKey, error) {
	r.calls.Add(1)
	return r.Repository.Introspect(ctx, claims, scope)
}

func newSQLConsumer(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *tokenservice.Service, keys *authjwt.PublicKeys) (*authjwt.Consumer, *consumerSQLAuthority) {
	t.Helper()
	secret, hash := introspectionCredential()
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
	if err != nil {
		t.Fatal(err)
	}
	repo := &consumerSQLAuthority{Repository: tokenpostgres.New(db)}
	online, err := tokenservice.NewIntrospection(repo, introspectionSQLBudget{}, keys, tokenservice.IntrospectionConfig{
		Issuer: "https://auth.example", ConsumerPerMinute: 100, ProjectPerMinute: 100,
		Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}},
		Clients:   []tokenservice.IntrospectionClientConfig{{ID: "orders-api", SecretHashes: []string{hash}, Audiences: []string{"orders"}}},
	}, catalog)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(router.New(router.Handlers{
		Config: &config.Config{JWT: tokensettings.Config{Enabled: true}}, Logger: zap.NewNop(),
		Tokens: tokenhttp.New(svc, keys.JWKS(), zap.NewNop()), Introspection: tokenhttp.NewIntrospection(online),
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	consumer, err := authjwt.NewConsumer(ctx, authjwt.ConsumerConfig{
		Expected: authjwt.Expectations{Issuer: "https://auth.example", Audience: "orders", Mode: authjwt.Strict},
		JWKSURL:  server.URL + "/.well-known/jwks.json", IntrospectionURL: server.URL + "/api/v1/internal/auth/token/introspect",
		ClientID: "orders-api", ClientSecret: secret, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(consumer.Close)
	return consumer, repo
}

func consumerSQLRequest(t *testing.T, consumer *authjwt.Consumer, raw, permission string, want int) {
	t.Helper()
	guard, err := authjwt.RequirePermissions(permission)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := consumer.Middleware(guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := authjwt.PrincipalFromContext(r.Context())
		if !ok || principal.HasPermission("orders.write") {
			t.Error("invalid effective principal")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	r := httptest.NewRequest(http.MethodGet, "https://orders.example/orders", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != want || called != (want == http.StatusNoContent) {
		t.Fatal(w.Code, w.Body.String(), called)
	}
	if want != http.StatusNoContent && w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable failure")
	}
}

func checkConsumerSQLAuthority(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("replay revokes strict access despite cached signature keys", func(t *testing.T) {
		svc, input, keys := nativeIssuanceFixture(t, db, ctx)
		issued, err := svc.IssueNative(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		consumer, repo := newSQLConsumer(t, db, ctx, svc, keys)
		consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 204)
		consumerSQLRequest(t, consumer, issued.Raw, "orders.write", 403)
		consumerSQLRequest(t, consumer, issued.Raw+"x", "orders.read", 401)
		if repo.calls.Load() != 2 {
			t.Fatal("authority decision cached", repo.calls.Load())
		}
		refresh := tokenservice.RefreshInput{Token: issued.RefreshToken, IP: input.IP}
		next, err := svc.Refresh(ctx, refresh)
		if err != nil {
			t.Fatal(err)
		}
		consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 204)
		consumerSQLRequest(t, consumer, next.Raw, "orders.read", 204)
		if _, err := svc.Refresh(ctx, refresh); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("replay", err)
		}
		consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 401)
		consumerSQLRequest(t, consumer, next.Raw, "orders.read", 401)
		if _, err := svc.Refresh(ctx, tokenservice.RefreshInput{Token: next.RefreshToken, IP: input.IP}); !errors.Is(err, tokendomain.ErrInvalidRefresh) {
			t.Fatal("successor survived replay", err)
		}
	})
	for _, operation := range []string{"logout", "auth version", "role revoke"} {
		t.Run(operation+" denies the next strict request", func(t *testing.T) {
			svc, input, keys := nativeIssuanceFixture(t, db, ctx)
			issued, err := svc.IssueNative(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			consumer, _ := newSQLConsumer(t, db, ctx, svc, keys)
			consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 204)
			switch operation {
			case "logout":
				if err := svc.Logout(ctx, tokenservice.RefreshInput{Token: issued.RefreshToken, IP: input.IP}); err != nil {
					t.Fatal(err)
				}
			case "auth version":
				accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, input.Proof.UserID)
			case "role revoke":
				accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE permission_key='orders.read' AND role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, input.Proof.UserID)
			}
			consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 401)
		})
	}
	t.Run("SQL unavailable has no signature-only fallback", func(t *testing.T) {
		svc, input, keys := nativeIssuanceFixture(t, db, ctx)
		issued, err := svc.IssueNative(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		onlineDB, err := pgxpool.NewWithConfig(ctx, db.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(onlineDB.Close)
		consumer, repo := newSQLConsumer(t, onlineDB, ctx, svc, keys)
		consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 204)
		onlineDB.Close()
		consumerSQLRequest(t, consumer, issued.Raw, "orders.read", 503)
		if repo.calls.Load() != 2 {
			t.Fatal("SQL failure hidden by cache", repo.calls.Load())
		}
	})
}

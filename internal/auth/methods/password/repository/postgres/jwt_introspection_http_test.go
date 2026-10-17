package postgres

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	tokenpostgres "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/postgres"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

type introspectionSQLBudget struct{}

func (introspectionSQLBudget) AllowIntrospection(context.Context, string, int, int) error { return nil }

func checkIntrospectionHTTP(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Run("signed token through authenticated HTTP to SQL", func(t *testing.T) {
		signer, keys := jwtSigningFixture(t)
		svc := nativeTokenService(t, db, signer)
		input := jwtActor(t, db, ctx)
		token, err := svc.Exchange(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		secret, hash := introspectionCredential()
		catalog, err := settings.NewCatalog([]settings.Permission{{Key: "orders.read", Name: "Read"}, {Key: "orders.write", Name: "Write"}})
		if err != nil {
			t.Fatal(err)
		}
		online, err := tokenservice.NewIntrospection(tokenpostgres.New(db), introspectionSQLBudget{}, keys, tokenservice.IntrospectionConfig{
			Issuer: "https://auth.example", ConsumerPerMinute: 100, ProjectPerMinute: 100,
			Resources: []tokenservice.Resource{{Audience: "orders", Permissions: []accessdomain.PermissionKey{"orders.read", "orders.write"}}},
			Clients:   []tokenservice.IntrospectionClientConfig{{ID: "orders-api", SecretHashes: []string{hash}, Audiences: []string{"orders"}}},
		}, catalog)
		if err != nil {
			t.Fatal(err)
		}
		h := tokenhttp.NewIntrospection(online)
		check := func(active bool) {
			t.Helper()
			data, err := json.Marshal(tokenhttp.IntrospectionRequest{Token: token.Raw})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "https://auth.example/api/v1/internal/auth/token/introspect", strings.NewReader(string(data))).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.SetBasicAuth("orders-api", secret)
			w := httptest.NewRecorder()
			h.Inspect(w, r)
			var result tokenhttp.IntrospectionResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Active != active {
				t.Fatal(w.Code, w.Body.String())
			}
			if active && (result.ID != token.ID || result.Subject != string(input.Actor.UserID) || result.SessionID != input.SessionID || result.Scope != "orders.read" || result.ExpiresAt != token.ExpiresAt.Unix()) {
				t.Fatal("uncorrelated result", result)
			}
			if !active && strings.TrimSpace(w.Body.String()) != `{"active":false}` {
				t.Fatal("inactive metadata", w.Body.String())
			}
		}
		check(true)
		accessExec(t, db, ctx, `UPDATE auth.users SET auth_version=auth_version+1 WHERE id=$1`, input.Actor.UserID)
		check(false)
	})
}

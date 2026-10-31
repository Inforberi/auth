package main

import (
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/admission"
	projectservice "github.com/Inforberi/financial-intelligence/internal/platform/project/service"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

// This focused composition uses production handlers/guards; full operator routing has separate tests.
func serveLifecycleOperator(t *testing.T, pair preparedHTTPProjects, f projectIsolationHTTP) (isolationHTTP, string) {
	t.Helper()
	ctx := t.Context()
	managed, actor := isolationPlatformOperator(t, ctx, pair)
	cfg, err := pgxpool.ParseConfig(pair.admin.Config().ConnString())
	require.NoError(t, err)
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "auth_platform_admin_isolation_test", "http-operator-fixture-only"
	cfg.MaxConns, cfg.MinConns = 2, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	authority, err := operatorpostgres.New(pool, operatordomain.RealmID(pair.a.Binding.RealmID))
	require.NoError(t, err)
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = pair.admin.Exec(ctx, `UPDATE auth.sessions SET token_hash=$1 WHERE token_hash=$2`, tokens.Hash(raw), actor.TokenHash)
	require.NoError(t, err)
	sessions := sessionservice.New(clock.UTCClock{}, sessionpostgres.New(pool), tokens, f.password.Session)
	auth := sessionhttp.New(sessions, zap.NewNop())
	service := projectservice.NewWithRuntime(managed, authority, isolationLifecycleObserver{realm: pair.a.Binding.RealmID, registry: f.deps.Registry})
	handler := projecthttp.New(service, zap.NewNop())
	gate, err := admission.New(f.deps.Redis, pair.a.Binding.RealmID, admission.DefaultConfig())
	require.NoError(t, err)
	scope, err := realmscope.New("platform", string(pair.a.Binding.RealmID))
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("platform-project-admission", "")
	require.NoError(t, err)
	for _, key := range []string{"global", "actor:" + string(actor.UserID), "project:" + string(pair.a.Binding.ProjectID), "project:" + string(pair.b.Binding.ProjectID)} {
		f.redisKeys[prefix+key] = struct{}{}
	}
	r := chi.NewRouter()
	r.Use(middleware.BrowserProtection(middleware.OriginConfig{AllowedOrigins: []string{"https://platform-http.example.test"}}), auth.NoRefreshAuth)
	r.With(projecthttp.Capacity(gate)).Post("/api/v1/platform/projects/{id}/suspend", handler.Suspend)
	r.With(projecthttp.Capacity(gate)).Post("/api/v1/platform/projects/{id}/resume", handler.Resume)
	r.With(projecthttp.Capacity(gate)).Post("/api/v1/platform/projects/{id}/retry", handler.Retry)
	server := httptest.NewTLSServer(r)
	t.Cleanup(server.Close)
	return isolationHTTP{server: server, origin: "https://platform-http.example.test"}, "__Host-session=" + raw
}

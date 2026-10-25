package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	tokenredis "github.com/Inforberi/financial-intelligence/internal/auth/token/repository/redis"
	tokenservice "github.com/Inforberi/financial-intelligence/internal/auth/token/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func (f projectProfileFixture) httpProfile(t *testing.T, ctx context.Context, origin string) {
	t.Helper()
	_, err := f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=true,registration_enabled=false,password_email_verification='disabled',email_otp_enabled=false,google_enabled=false,telegram_enabled=false,token_session_exchange_enabled=true,token_native_enabled=false`)
	require.NoError(t, err)
	issuance, err := appauth.NewProjectTokenRedis(f.rdb)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, issuance.Close()) })
	password := projectPasswordFixtureConfig()
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read reports"}})
	require.NoError(t, err)
	tokens := appauth.ProjectTokenConfig{Enabled: true, Issuer: origin, Catalog: catalog, Limits: tokenredis.DefaultLimits(), Timeout: 5 * time.Second, Tokens: tokenservice.Config{AccessTTL: time.Minute, Resources: []tokenservice.Resource{{Audience: "reports", Permissions: []accessdomain.PermissionKey{"reports.read"}}}}}
	features := appauth.ProjectProfileConfig{BrowserEnabled: true, Password: &password, Tokens: &tokens, Timeout: 10 * time.Second}
	deps := appauth.ProjectProfileDependencies{ProjectTokenDependencies: appauth.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, IssuanceRedis: issuance, Hash: f.hash}}
	var builds atomic.Int32
	handler, err := appauth.NewProjectHTTP(appauth.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 20 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &password.Session,
	}, deps, func(context.Context, projectruntime.Key, string) (appauth.ProjectProfileConfig, error) {
		builds.Add(1)
		return features, nil
	}, nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	f.httpLoginLimitCleanup(t, ctx)
	host, err := url.Parse(origin)
	require.NoError(t, err)
	request := func(path, requestOrigin, cookie, body string) (int, []*http.Cookie) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		r.Host = host.Host
		r.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		return response.StatusCode, response.Cookies()
	}
	code, _ := request("/api/v1/auth/login/email", "", "", `{}`)
	require.Equal(t, 403, code)
	code, _ = request("/api/v1/auth/login/email", "https://foreign.example.test", "", `{}`)
	require.Equal(t, 403, code)
	code, cookies := request("/api/v1/auth/login/email", origin, "", `{"email":"runtime-email@example.test","password":"`+f.password+`"}`)
	require.Equal(t, 200, code)
	var session *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "__Host-session" {
			session = cookie
		}
	}
	require.NotNil(t, session)
	require.True(t, session.Secure && session.HttpOnly)
	require.Empty(t, session.Domain)
	require.Equal(t, "/", session.Path)
	cookie := session.Name + "=" + session.Value
	code, _ = request("/api/v1/auth/token/exchange", origin, "", `{}`)
	require.Equal(t, 401, code)
	code, _ = request("/api/v1/auth/token/exchange", origin, cookie, `!`)
	require.Equal(t, 400, code, "valid SQL session reaches existing JSON handler")
	require.EqualValues(t, 1, builds.Load(), "warm requests must not rebuild profile")
	_, err = f.db.Exec(ctx, `UPDATE auth.users SET status='blocked' WHERE id=$1`, f.sourceUser)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `UPDATE auth.users SET status='active' WHERE id=$1`, f.sourceUser)
		require.NoError(t, err)
	})
	code, _ = request("/api/v1/auth/token/exchange", origin, cookie, `!`)
	require.Equal(t, 401, code)
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=false`)
	require.NoError(t, err)
	code, _ = request("/api/v1/auth/login/email", origin, "", `{}`)
	require.Equal(t, 404, code, "stale profile is rejected")
	code, _ = request("/api/v1/auth/login/email", origin, "", `{}`)
	require.Equal(t, 404, code, "rebuilt profile does not mount disabled password")
	require.EqualValues(t, 2, builds.Load())
	code, _ = request("/api/v1/admin/auth/login/email", origin, "", `{}`)
	require.Equal(t, 404, code)
	_, err = f.admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1 WHERE id=$1`, f.key.Binding.ProjectID)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.admin.Exec(cleanup, `UPDATE platform.projects SET desired_state='enabled',version=$2 WHERE id=$1`, f.key.Binding.ProjectID, f.key.Version)
		require.NoError(t, err)
	})
	code, _ = request("/api/v1/auth/token/exchange", origin, cookie, `!`)
	require.Equal(t, 404, code)
	require.EqualValues(t, 2, builds.Load(), "suspended projects never load profiles")
}

func (f projectProfileFixture) httpLoginLimitCleanup(t *testing.T, ctx context.Context) {
	t.Helper()
	configuration, err := f.deps.Reader.LoadAuthConfiguration(ctx, f.key, f.deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(f.key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("password-reset:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	keys := []string{prefix + cipher.Digest("login-ip:127.0.0.1"), prefix + cipher.Digest("login-email:runtime-email@example.test"), prefix + cipher.Digest("login-global")}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, f.rdb.Del(cleanup, keys...).Err())
	})
}

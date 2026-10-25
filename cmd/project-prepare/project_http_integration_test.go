package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	"github.com/Inforberi/financial-intelligence/internal/config"
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
	deploymentConfig := &config.Config{
		Session: password.Session, Capacity: password.Capacity,
		MFA: mfaservice.Config{Enabled: true, Issuer: "Project", ChallengeTTL: time.Minute, UserLimitPerMinute: 30, IPLimitPerMinute: 50, GlobalLimitPerMinute: 100},
		JWT: tokensettings.Config{AccessTTL: time.Minute, RefreshIdleTTL: time.Hour, RefreshAbsoluteTTL: 2 * time.Hour, ActorPerMinute: 30, SessionPerMinute: 10, IPPerMinute: 30, ProjectPerMinute: 3000, IntrospectionConsumerPerMinute: 100, IntrospectionProjectPerMinute: 1000},
	}
	deploymentConfig.Platform.RealmID = string(f.key.Binding.RealmID)
	deploymentConfig.Platform.HTTP.BuildTimeout = 5 * time.Second
	deploymentConfig.Platform.HTTP.ManifestFile = filepath.Join(t.TempDir(), "project-auth.json")
	manifest := fmt.Sprintf(`{"version":1,"projects":[{"id":%q,"browser":true,"jwt":{"native":true,"password":true,"permissions":[{"key":"reports.read","name":"Read reports"}],"resources":[{"audience":"reports","permissions":["reports.read"]}],"clients":[{"id":"consumer","secretHashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"audiences":["reports"]}]}}]}`, string(f.key.Binding.ProjectID))
	require.NoError(t, os.WriteFile(deploymentConfig.Platform.HTTP.ManifestFile, []byte(manifest), 0o600))
	deployment, err := appauth.LoadProjectAuthDeployment(deploymentConfig)
	require.NoError(t, err)
	deps := appauth.ProjectProfileDependencies{ProjectTokenDependencies: appauth.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, IssuanceRedis: issuance, Hash: f.hash}}
	var builds atomic.Int32
	handler, err := appauth.NewProjectHTTP(appauth.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-http.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 20 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &password.Session,
	}, deps, func(ctx context.Context, key projectruntime.Key, origin string) (appauth.ProjectProfileConfig, error) {
		builds.Add(1)
		return deployment.Profile(ctx, key, origin)
	}, nil)
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=false`)
	require.NoError(t, err)
	assessment, err := handler.Assess(ctx, f.key, origin)
	require.NoError(t, err)
	require.True(t, assessment.Runtime.Methods.Password, "disabled SQL method must not hide potential capability")
	require.True(t, assessment.Runtime.Tokens.Native)
	require.True(t, assessment.Runtime.Tokens.SessionExchange)
	require.Len(t, assessment.Tokens.Resources, 1)
	require.Equal(t, "reports", assessment.Tokens.Resources[0].Audience)
	require.False(t, assessment.Runtime.VerificationReady, "mail is not configured for this deployment")
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=true`)
	require.NoError(t, err)
	builds.Store(0)
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
	code, _ = request("/api/v1/internal/auth/token/introspect", "", "", `!`)
	require.Equal(t, 401, code)
	code, _ = request("/api/v1/internal/auth/token/introspect", origin, "", `!`)
	require.Equal(t, 403, code)
	code, _ = request("/api/v1/auth/native/password/login", "", "", `!`)
	require.Equal(t, 404, code)
	_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,token_native_enabled=true`)
	require.NoError(t, err)
	code, _ = request("/api/v1/auth/native/password/login", "", "", `!`)
	require.Equal(t, 404, code)
	code, _ = request("/api/v1/auth/native/password/login", "", "", `!`)
	require.Equal(t, 400, code, "current enabled native profile reaches strict JSON handler")
	require.EqualValues(t, 2, builds.Load())

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
	require.EqualValues(t, 3, builds.Load())
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
	require.EqualValues(t, 3, builds.Load(), "suspended projects never load profiles")
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

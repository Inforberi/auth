package projects_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	profilefactory "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

func projectMFAManagementHTTPDrill(t *testing.T, admin, db *pgx.Conn, rdb *redis.Client, key projectruntime.Key, cfg projectmethods.ProjectPasswordConfig, deps projectmethods.ProjectPasswordDependencies, input passwordservice.LoginInput) {
	t.Helper()
	ctx := t.Context()
	cfg.MFA = mfaservice.Config{Enabled: true, Issuer: "Project MFA management", ChallengeTTL: time.Minute, UserLimitPerMinute: 100, IPLimitPerMinute: 100, GlobalLimitPerMinute: 100}
	_, err := db.Exec(ctx, `CREATE TEMP TABLE mfa_management_policy_before AS TABLE auth.auth_settings;
UPDATE auth.auth_settings SET password_enabled=true,password_email_verification='disabled',version=version+1`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.mfa_audit WHERE user_id=$1;
DELETE FROM auth.mfa_login_challenges WHERE user_id=$1;
DELETE FROM auth.mfa_enrollments WHERE user_id=$1;
DELETE FROM auth.mfa_recovery_codes WHERE user_id=$1;
DELETE FROM auth.mfa_totp WHERE user_id=$1;
DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN(SELECT id FROM auth.roles WHERE key='project_mfa_management_required');
DELETE FROM auth.roles WHERE key='project_mfa_management_required';
DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM mfa_management_policy_before`, passwordFixtureUser)
		require.NoError(t, err)
	})
	configuration, err := deps.Reader.LoadAuthConfiguration(ctx, key, deps.Registry)
	require.NoError(t, err)
	scope, err := realmscope.New("project", string(key.Binding.ProjectID))
	require.NoError(t, err)
	purpose, err := scope.Purpose("mfa:v1")
	require.NoError(t, err)
	cipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	prefix, err := scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	keys := []string{prefix + cipher.Digest("user:"+passwordFixtureUser), prefix + cipher.Digest("login:factor-user:"+passwordFixtureUser), prefix + cipher.Digest("step-up:"+passwordFixtureUser), prefix + "login:ip:" + cipher.Digest("127.0.0.1"), prefix + "project"}
	purpose, err = scope.Purpose("password-reset:v1")
	require.NoError(t, err)
	passwordCipher, err := secretbox.NewScoped(configuration.EncryptionKey(), purpose)
	require.NoError(t, err)
	passwordPrefix, err := scope.RedisPrefix("password-limit", "auth:password-recovery:limit:")
	require.NoError(t, err)
	keys = append(keys, passwordPrefix+passwordCipher.Digest("login-ip:127.0.0.1"))
	keys = append(keys, passwordPrefix+passwordCipher.Digest("reauth-user:"+passwordFixtureUser))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, rdb.Del(cleanup, keys...).Err())
	})
	var origin string
	require.NoError(t, admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, key.Binding.ProjectID).Scan(&origin))
	handler, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-mfa.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 20 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &cfg.Session,
	}, runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: deps.Registry, Reader: deps.Reader, Redis: rdb, Hash: deps.Hash}}.Reader, profilefactory.NewFactory(runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: deps.Registry, Reader: deps.Reader, Redis: rdb, Hash: deps.Hash}}, func(_ context.Context, selected projectruntime.Key, selectedOrigin string) (runtimeprofile.ProjectProfileConfig, error) {
		require.Equal(t, key, selected)
		require.Equal(t, origin, selectedOrigin)
		return runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &cfg, Timeout: 10 * time.Second}, nil
	}), nil)
	require.NoError(t, err)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		require.NoError(t, handler.Close(cleanup))
	})
	host, err := url.Parse(origin)
	require.NoError(t, err)
	request := func(method, path, requestOrigin, cookie, body string) (int, []byte, []*http.Cookie) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+"/api/v1/auth"+path, strings.NewReader(body))
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
		data, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			require.Contains(t, response.Header.Get("Cache-Control"), "no-store")
		}
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		return response.StatusCode, data, response.Cookies()
	}
	cookieValue := func(cookies []*http.Cookie) string {
		t.Helper()
		for _, cookie := range cookies {
			if cookie.Name == "__Host-session" {
				require.True(t, cookie.HttpOnly && cookie.Secure)
				require.Empty(t, cookie.Domain)
				return cookie.Name + "=" + cookie.Value
			}
		}
		t.Fatal("missing session cookie")
		return ""
	}
	login := func(secondFactor string, recovery bool) string {
		t.Helper()
		code, data, cookies := request("POST", "/login/email", origin, "", `{"email":"`+input.Email+`","password":"`+input.Password+`"}`)
		if secondFactor == "" {
			require.Equal(t, 200, code)
			return cookieValue(cookies)
		}
		require.Equal(t, 202, code)
		var challenge mfaloginhttp.ChallengeResponse
		require.NoError(t, json.Unmarshal(data, &challenge))
		require.NotEmpty(t, challenge.Challenge)
		binding := ""
		for _, cookie := range cookies {
			if cookie.Name == mfaloginhttp.LoginCookie {
				require.True(t, cookie.HttpOnly && cookie.Secure)
				require.Empty(t, cookie.Domain)
				require.Equal(t, "/", cookie.Path)
				binding = cookie.Value
			}
		}
		require.Len(t, binding, 43)
		keys = append(keys, prefix+"login:complete:subject:"+cipher.Digest(challenge.Challenge+":"+binding))
		payload, err := json.Marshal(mfaloginhttp.CompleteLoginRequest{Challenge: challenge.Challenge, Code: secondFactor, Recovery: recovery})
		require.NoError(t, err)
		code, _, cookies = request("POST", "/mfa/login/complete", origin, mfaloginhttp.LoginCookie+"="+binding, string(payload))
		require.Equal(t, 200, code)
		// Ordinary MFA login does not grant the separate sensitive-operation password proof.
		code, _, cookies = request("POST", "/reauthenticate/password", origin, cookieValue(cookies), `{"password":"`+input.Password+`"}`)
		require.Equal(t, 200, code)
		return cookieValue(cookies)
	}
	status := func(cookie string) mfamanagementhttp.SecurityStatusResponse {
		t.Helper()
		code, data, cookies := request("GET", "/mfa/status", "", cookie, "")
		require.Equal(t, 200, code)
		require.Empty(t, cookies, "status must not extend the session")
		var result mfamanagementhttp.SecurityStatusResponse
		require.NoError(t, json.Unmarshal(data, &result))
		return result
	}
	confirm := func(path, cookie string, enrollment mfahttp.EnrollmentResponse) []string {
		t.Helper()
		codeValue := projectMFACode(t, ctx, db, enrollment.Secret, 0)
		code, data, cookies := request("POST", path, origin, cookie, `{"token":"`+enrollment.Token+`","code":"`+codeValue+`"}`)
		require.Equal(t, 200, code)
		require.Equal(t, "__Host-session=", cookieValue(cookies))
		var result mfahttp.RecoveryCodesResponse
		require.NoError(t, json.Unmarshal(data, &result))
		require.Len(t, result.Codes, 10)
		return result.Codes
	}
	current := login("", false)
	require.False(t, status(current).TOTPEnabled)
	code, _, _ := request("POST", "/mfa/totp/enrollment", "", current, "")
	require.Equal(t, 403, code)
	code, _, _ = request("GET", "/mfa/status", "", "", "")
	require.Equal(t, 401, code)
	_, err = db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, tokengenerate.New().Hash(strings.TrimPrefix(current, "__Host-session=")))
	require.NoError(t, err)
	require.False(t, status(current).FreshPrimaryProof)
	code, _, _ = request("POST", "/mfa/totp/enrollment", origin, current, "")
	require.Equal(t, 403, code)
	_, err = db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE token_hash=$1`, tokengenerate.New().Hash(strings.TrimPrefix(current, "__Host-session=")))
	require.NoError(t, err)
	code, data, _ := request("POST", "/mfa/totp/enrollment", origin, current, "")
	require.Equal(t, 200, code)
	var enrollment mfahttp.EnrollmentResponse
	require.NoError(t, json.Unmarshal(data, &enrollment))
	require.NotEmpty(t, enrollment.Secret)
	recovery := confirm("/mfa/totp/enrollment/confirm", current, enrollment)
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 401, code)
	current = login(recovery[0], true)
	require.True(t, status(current).TOTPEnabled)
	var expires, absolute time.Time
	require.NoError(t, db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(strings.TrimPrefix(current, "__Host-session="))).Scan(&expires, &absolute))
	previous := current
	code, data, cookies := request("POST", "/mfa/step-up", origin, current, `{"code":"`+recovery[1]+`","recovery":true}`)
	require.Equal(t, 200, code)
	var stepped mfamanagementhttp.StepUpResponse
	require.NoError(t, json.Unmarshal(data, &stepped))
	require.False(t, stepped.VerifiedAt.IsZero())
	current = cookieValue(cookies)
	require.NotEqual(t, previous, current)
	code, _, _ = request("GET", "/mfa/status", "", previous, "")
	require.Equal(t, 401, code)
	var nowExpires, nowAbsolute time.Time
	require.NoError(t, db.QueryRow(ctx, `SELECT expires_at,absolute_expires_at FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(strings.TrimPrefix(current, "__Host-session="))).Scan(&nowExpires, &nowAbsolute))
	require.Equal(t, expires, nowExpires)
	require.Equal(t, absolute, nowAbsolute)
	code, _, _ = request("POST", "/mfa/step-up", origin, current, `{"code":"`+recovery[1]+`","recovery":true}`)
	require.Equal(t, 400, code)
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=false,email_otp_enabled=false,google_enabled=false,telegram_enabled=false,version=version+1`)
	require.NoError(t, err)
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 404, code)
	require.True(t, status(current).TOTPEnabled, "management survives disabled primary methods")
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=true,version=version+1`)
	require.NoError(t, err)
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 404, code)
	require.True(t, status(current).FreshMFAProof)
	_, err = db.Exec(ctx, `WITH r AS(INSERT INTO auth.roles(key,name,mfa_required) VALUES('project_mfa_management_required','Fixture required MFA',true) RETURNING id) INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, passwordFixtureUser)
	require.NoError(t, err)
	current = login(recovery[2], true)
	require.True(t, status(current).RequiredByRole)
	code, _, _ = request("DELETE", "/mfa/totp", origin, current, "")
	require.Equal(t, 403, code)
	require.True(t, status(current).TOTPEnabled)
	_, err = db.Exec(ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id IN(SELECT id FROM auth.roles WHERE key='project_mfa_management_required')`, passwordFixtureUser)
	require.NoError(t, err)
	current = login(recovery[3], true)
	code, data, cookies = request("POST", "/mfa/recovery-codes/regenerate", origin, current, "")
	require.Equal(t, 200, code)
	require.Equal(t, "__Host-session=", cookieValue(cookies))
	var regenerated mfahttp.RecoveryCodesResponse
	require.NoError(t, json.Unmarshal(data, &regenerated))
	require.Len(t, regenerated.Codes, 10)
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 401, code)
	var oldCodeExists bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=$1 AND digest=$2)`, passwordFixtureUser, cipher.Digest("recovery:"+passwordFixtureUser+":"+recovery[4])).Scan(&oldCodeExists))
	require.False(t, oldCodeExists)
	current = login(regenerated.Codes[0], true)
	code, data, _ = request("POST", "/mfa/totp/replacement", origin, current, "")
	require.Equal(t, 200, code)
	var replacement mfahttp.EnrollmentResponse
	require.NoError(t, json.Unmarshal(data, &replacement))
	require.True(t, status(current).TOTPEnabled)
	replacementCodes := confirm("/mfa/totp/replacement/confirm", current, replacement)
	require.Len(t, replacementCodes, 10)
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 401, code)
	current = login(projectMFACode(t, ctx, db, replacement.Secret, 30*time.Second), false)
	code, _, cookies = request("DELETE", "/mfa/totp", origin, current, "")
	require.Equal(t, 200, code)
	require.Equal(t, "__Host-session=", cookieValue(cookies))
	code, _, _ = request("GET", "/mfa/status", "", current, "")
	require.Equal(t, 401, code)
	current = login("", false)
	require.False(t, status(current).TOTPEnabled)
}

package projects_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/hasher"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/transport/http/projects"
)

type projectIdentityHTTPFixture struct {
	admin, db  *pgx.Conn
	rdb        *redis.Client
	key        projectruntime.Key
	deps       projectbinding.ProjectSMTPDependencies
	clients    *projectmethods.ProjectOIDCClients
	ciphers    map[string]*secretbox.Cipher
	prefixes   map[string]string
	keys       *[]string
	sourceUser string
	hash       *hasher.Bounded
}

func (f projectIdentityHTTPFixture) run(t *testing.T, ctx context.Context) {
	t.Helper()
	var origin string
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, f.key.Binding.ProjectID).Scan(&origin))
	var password, google, telegram bool
	var verification string
	var version int64
	require.NoError(t, f.db.QueryRow(ctx, `SELECT password_enabled,google_enabled,telegram_enabled,version,password_email_verification FROM auth.auth_settings`).Scan(&password, &google, &telegram, &version, &verification))
	users := []string{"f8600000-0000-4000-8000-000000000001", "f8600000-0000-4000-8000-000000000002"}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.identity_audit WHERE user_id=ANY($1::uuid[]);
DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[]);
DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
UPDATE auth.auth_settings SET password_enabled=$2,google_enabled=$3,telegram_enabled=$4,version=$5,password_email_verification=$6`, users, password, google, telegram, version, verification)
		require.NoError(t, err)
	})
	_, err := f.db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=true,google_enabled=true,telegram_enabled=true,password_email_verification='disabled',version=version+1`)
	require.NoError(t, err)
	passwordConfig := projectPasswordFixtureConfig()
	session := passwordConfig.Session
	provider := func(name string) *projectmethods.ProjectOIDCConfig {
		return &projectmethods.ProjectOIDCConfig{Provider: name, Enabled: true, RedirectURI: origin + "/api/v1/auth/" + name + "/callback", IPLimit: 30, GlobalLimit: 1000, Session: session, Timeout: 10 * time.Second}
	}
	handler, err := projectbrowser.NewProjectHTTP(runtimeprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-identity.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 20 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 10 * time.Second}, SessionValidation: &session,
	}, runtimeprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader, Redis: f.rdb, Hash: f.hash}, OIDCClients: f.clients}, func(_ context.Context, key projectruntime.Key, selected string) (runtimeprofile.ProjectProfileConfig, error) {
		require.Equal(t, f.key, key)
		require.Equal(t, origin, selected)
		return runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &passwordConfig, Google: provider("google"), Telegram: provider("telegram"), Timeout: 10 * time.Second}, nil
	}, nil)
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
	request := func(method, path, requestOrigin, cookies string) (int, []byte, []*http.Cookie) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, nil)
		require.NoError(t, err)
		r.Host = host.Host
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if cookies != "" {
			r.Header.Set("Cookie", cookies)
		}
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		return response.StatusCode, body, response.Cookies()
	}
	for index, name := range []string{"google", "telegram"} {
		user := users[index]
		raw, err := tokengenerate.New().GenerateToken()
		require.NoError(t, err)
		issuer := settingsdomain.ProviderIssuer(name)
		_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1);
INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp());
INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT $1,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$1 AND p.user_id=$3;
INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,password_verified_at,primary_method,primary_verified_at,user_agent,ip_address) VALUES($4,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',clock_timestamp(),'password',clock_timestamp(),'project-identity-http-fixture','127.0.0.1');
INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,$5,$6)`, user, "identity-http-"+name+"@example.test", f.sourceUser, tokengenerate.New().Hash(raw), issuer, strconv.Itoa(86000001+index))
		require.NoError(t, err)
		cookie := "__Host-session=" + raw
		path := "/api/v1/auth/" + name + "/link"
		*f.keys = append(*f.keys, f.prefixes[name]+":limit:"+f.ciphers[name].Digest("127.0.0.1"))
		code, _, _ := request("POST", path, "", cookie)
		require.Equal(t, 403, code)
		code, _, _ = request("DELETE", path, "https://foreign.example.test", cookie)
		require.Equal(t, 403, code)
		code, _, _ = request("POST", path, origin, "")
		require.Equal(t, 401, code)
		_, err = f.db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE user_id=$1`, user)
		require.NoError(t, err)
		code, _, _ = request("POST", path, origin, cookie)
		require.Equal(t, 403, code)
		_, err = f.db.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp() WHERE user_id=$1`, user)
		require.NoError(t, err)
		code, body, cookies := request("POST", path, origin, cookie)
		require.Equal(t, 200, code)
		var started struct {
			AuthorizationURL string `json:"authorizationUrl"`
		}
		require.NoError(t, json.Unmarshal(body, &started))
		authorize, err := url.Parse(started.AuthorizationURL)
		require.NoError(t, err)
		require.Equal(t, origin+"/api/v1/auth/"+name+"/callback", authorize.Query().Get("redirect_uri"))
		state := authorize.Query().Get("state")
		require.Len(t, state, 43)
		*f.keys = append(*f.keys, f.prefixes[name]+":flow:"+f.ciphers[name].Digest(state))
		var flowCookie string
		for _, value := range cookies {
			require.NotEqual(t, "__Host-session", value.Name, "link start must not issue or refresh login")
			if value.Name == "__Host-"+name+"-flow" {
				require.True(t, value.Secure && value.HttpOnly)
				require.Empty(t, value.Domain)
				flowCookie = value.Name + "=" + value.Value
			}
		}
		require.NotEmpty(t, flowCookie)
		_, err = f.db.Exec(ctx, `UPDATE auth.provider_settings SET version=version+1 WHERE provider=$1`, name)
		require.NoError(t, err)
		callback := "/api/v1/auth/" + name + "/callback?code=synthetic-unused-code&state=" + url.QueryEscape(state)
		code, _, _ = request("GET", callback, "", cookie+"; "+flowCookie)
		require.Equal(t, 400, code, "provider rotation rejects before external exchange")
		code, _, _ = request("GET", callback, "", cookie+"; "+flowCookie)
		require.Equal(t, 400, code, "state cannot be reused")
		var issued int
		require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, user).Scan(&issued))
		require.Equal(t, 1, issued, "link start/rejected callback must not create a session")
		_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=false,version=version+1`)
		require.NoError(t, err)
		code, _, _ = request("DELETE", path, origin, cookie)
		require.Equal(t, 404, code)
		code, body, cookies = request("DELETE", path, origin, cookie)
		require.Equal(t, 409, code)
		require.Contains(t, string(body), "last_login_method")
		require.Empty(t, cookies)
		_, err = f.db.Exec(ctx, `UPDATE auth.auth_settings SET password_enabled=true,version=version+1`)
		require.NoError(t, err)
		code, _, _ = request("DELETE", path, origin, cookie)
		require.Equal(t, 404, code)
		code, _, cookies = request("DELETE", path, origin, cookie)
		require.Equal(t, 204, code)
		require.NotEmpty(t, cookies)
		for _, value := range cookies {
			require.Empty(t, value.Value, "unlink clears cookies rather than authenticating")
		}
		code, _, _ = request("GET", "/api/v1/auth/me", "", cookie)
		require.Equal(t, 401, code)
		var remaining int
		var authVersion int64
		require.NoError(t, f.db.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth.linked_identities WHERE user_id=$1),auth_version FROM auth.users WHERE id=$1`, user).Scan(&remaining, &authVersion))
		require.Zero(t, remaining)
		require.EqualValues(t, 2, authVersion)
	}
}

package projects_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectbrowser "github.com/Inforberi/financial-intelligence/internal/app/projects/browser"
	projectnative "github.com/Inforberi/financial-intelligence/internal/app/projects/native"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func (f projectProfileFixture) httpUserDirectory(t *testing.T, ctx context.Context, origin string) {
	t.Helper()
	const actor = "f8500000-0000-4000-8000-000000000001"
	const ordinary = "f8500000-0000-4000-8000-000000000002"
	const absent = "f8500000-0000-4000-8000-000000000099"
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	other, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1),($2);
 INSERT INTO auth.roles(key,name) VALUES('project_directory_fixture_reader','Directory reader');
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$3 FROM auth.roles WHERE key='project_directory_fixture_reader';
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='project_directory_fixture_reader';
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 VALUES($4,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'directory-fixture','192.0.2.85'),
 ($5,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'directory-fixture','192.0.2.85')`, actor, ordinary, string(accesssettings.UsersRead), tokens.Hash(raw), tokens.Hash(other))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.user_roles WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
 DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key='project_directory_fixture_reader');
 DELETE FROM auth.roles WHERE key='project_directory_fixture_reader'`, []string{actor, ordinary})
		require.NoError(t, err)
	})
	session := projectPasswordFixtureConfig().Session
	handler, err := projectbrowser.NewProjectHTTP(projectprofile.ProjectHTTPConfig{
		PlatformOrigin: "https://platform-directory.example.test", Residents: projecthttp.RuntimeDispatcherConfig{MaxProfiles: 2, MaxBuilding: 1, BuildTimeout: 10 * time.Second, MaxAge: time.Minute}, Capacity: middleware.CapacityConfig{MaxInFlight: 8, RequestTimeout: 5 * time.Second}, SessionValidation: &session,
	}, projectprofile.ProjectProfileDependencies{ProjectTokenDependencies: projectnative.ProjectTokenDependencies{Registry: f.deps.Registry, Reader: f.deps.Reader}}, func(_ context.Context, key projectruntime.Key, selected string) (projectprofile.ProjectProfileConfig, error) {
		require.Equal(t, f.key, key)
		require.Equal(t, origin, selected)
		return projectprofile.ProjectProfileConfig{BrowserEnabled: true, UserDirectoryEnabled: true, Timeout: 5 * time.Second}, nil
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
	request := func(method, path, requestOrigin, cookie string, expected int) string {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, nil)
		require.NoError(t, err)
		r.Host = host.Host
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: cookie})
		}
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, expected, response.StatusCode, "%s %s: %s", method, path, body)
		require.Empty(t, response.Cookies())
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		return string(body)
	}
	const path = "/api/v1/admin/users"
	request("GET", path, "", "", 401)
	request("GET", path, "https://foreign.example.test", raw, 403)
	request("GET", path, "", other, 403)
	request("GET", path+"/"+actor, "", other, 403)
	request("GET", path+"/"+absent, "", other, 403)
	var before, after string
	const sessionState = `SELECT row_to_json(s)::text FROM auth.sessions s WHERE token_hash=$1`
	require.NoError(t, f.db.QueryRow(ctx, sessionState, tokens.Hash(raw)).Scan(&before))
	body := request("GET", path+"?limit=1", "", raw, 200)
	require.Contains(t, body, `"nextCursor"`)
	body = request("GET", path+"/"+ordinary, origin, raw, 200)
	require.Contains(t, body, ordinary)
	for _, secret := range []string{"passwordHash", "tokenHash", "subject", "secret", raw, other} {
		require.NotContains(t, body, secret)
	}
	request("GET", path+"/"+absent, "", raw, 404)
	request("GET", path+"?limit=101", "", raw, 400)
	request("GET", path+"?limit=1&limit=2", "", raw, 400)
	request("POST", path, origin, raw, 405)
	request("GET", path+"?email="+url.QueryEscape("No-Such-User@example.test"), "", raw, 200)
	require.NoError(t, f.db.QueryRow(ctx, sessionState, tokens.Hash(raw)).Scan(&after))
	require.Equal(t, before, after, "directory reads must not mutate the session")
	_, err = f.db.Exec(ctx, `DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key='project_directory_fixture_reader')`)
	require.NoError(t, err)
	request("GET", path, "", raw, 403)
	_, err = f.db.Exec(ctx, `UPDATE auth.roles SET session_revision=session_revision+1 WHERE key='project_directory_fixture_reader'`)
	require.NoError(t, err)
	request("GET", path, "", raw, 401)
	fresh, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 SELECT $2,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'directory-fixture','192.0.2.85' FROM auth.users WHERE id=$1`, actor, tokens.Hash(fresh))
	require.NoError(t, err)
	// A fresh session must still be denied after the permission was removed.
	request("GET", path, "", fresh, 403)
}

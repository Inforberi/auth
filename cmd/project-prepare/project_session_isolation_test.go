package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	appauth "github.com/Inforberi/financial-intelligence/internal/app/auth"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func TestTwoProjectSessionLifecycleIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	ctx := t.Context()
	for i, db := range f.databases {
		seedHTTPAdministrators(t, ctx, db)
		_, err := db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key)
 SELECT id,unnest(ARRAY['accounts.users.status.manage','accounts.users.delete']) FROM auth.roles WHERE key='super_admin'`)
		require.NoError(t, err)
		f.redisKeys[f.passwordPrefix[i]+f.passwordCipher[i].Digest("reauth-user:"+httpOwnerID)] = struct{}{}
	}
	f.trackLogin(httpOwnerEmail)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, db := range f.databases {
			for _, table := range []string{"account_status_audit", "account_deletion_audit"} {
				_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE user_id=$1`, httpIsolationUser)
				require.NoError(t, err)
			}
		}
	})
	webs, _, _ := f.serve(t, appauth.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, UserLifecycleEnabled: true, Timeout: 5 * time.Second})
	checkProjectSessionIsolation(t, ctx, webs)
	checkProjectLifecycleIsolation(t, ctx, f, webs)
}

func isolationSessionLogin(t *testing.T, ctx context.Context, web isolationHTTP) string {
	t.Helper()
	response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword})
	require.Equal(t, 200, response.status, "%s", response.body)
	return response.cookie(t, "__Host-session")
}

func checkProjectSessionIsolation(t *testing.T, ctx context.Context, webs [2]isolationHTTP) {
	t.Helper()
	const me = "/api/v1/auth/me"
	var cookies [2][2]string
	var sessions [2][2]sessionhttp.MeResponse
	for i, web := range webs {
		for j := range cookies[i] {
			cookies[i][j] = isolationSessionLogin(t, ctx, web)
			isolationCommand(t, ctx, web, "GET", me, cookies[i][j], nil, 200, &sessions[i][j])
		}
	}
	peer := func() {
		t.Helper()
		for _, cookie := range cookies[1] {
			isolationCommand(t, ctx, webs[1], "GET", me, cookie, nil, 200, nil)
		}
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "DELETE", "/api/v1/auth/sessions/"+sessions[1-i][1].SessionID, cookies[i][0], nil, 404, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/logout-all", cookies[1-i][0], nil, 401, nil)
		var listed sessionhttp.SessionsResponse
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/sessions", cookies[i][0], nil, 200, &listed)
		require.Len(t, listed.Sessions, 2)
		for _, session := range listed.Sessions {
			require.NotEqual(t, sessions[1-i][0].SessionID, session.ID)
			require.NotEqual(t, sessions[1-i][1].SessionID, session.ID)
		}
	}
	path := "/api/v1/auth/sessions/" + sessions[0][1].SessionID
	isolationCommand(t, ctx, webs[0], "DELETE", path, cookies[0][0], nil, 204, nil)
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0][1], nil, 401, nil)
	isolationCommand(t, ctx, webs[0], "DELETE", path, cookies[0][0], nil, 404, nil)
	peer()
	rotated := webs[0].call(t, ctx, "POST", "/api/v1/auth/session/rotate", webs[0].origin, cookies[0][0], nil)
	require.Equal(t, 204, rotated.status, "%s", rotated.body)
	current := rotated.cookie(t, "__Host-session")
	require.NotEqual(t, cookies[0][0], current)
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0][0], nil, 401, nil)
	var same sessionhttp.MeResponse
	isolationCommand(t, ctx, webs[0], "GET", me, current, nil, 200, &same)
	require.Equal(t, sessions[0][0].SessionID, same.SessionID)
	isolationCommand(t, ctx, webs[0], "POST", "/api/v1/auth/logout", current, nil, 204, nil)
	isolationCommand(t, ctx, webs[0], "GET", me, current, nil, 401, nil)
	peer()
	first, second := isolationSessionLogin(t, ctx, webs[0]), isolationSessionLogin(t, ctx, webs[0])
	isolationCommand(t, ctx, webs[0], "POST", "/api/v1/auth/logout-all", first, nil, 204, nil)
	for _, cookie := range []string{first, second} {
		isolationCommand(t, ctx, webs[0], "GET", me, cookie, nil, 401, nil)
	}
	peer()
}

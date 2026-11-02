package projects_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

type (
	oidcHTTPFlow  struct{ state, code, cookie string }
	oidcHTTPLogin struct{ user, cookie string }
)

func (f oidcIsolationFixture) start(t *testing.T, ctx context.Context, project int, name string) oidcHTTPFlow {
	t.Helper()
	web := f.webs[project]
	response := web.call(t, ctx, "POST", "/api/v1/auth/"+name+"/start", web.origin, "", nil)
	require.Equal(t, 200, response.status, "%s", response.body)
	var started oidchttp.StartResponse
	require.NoError(t, json.Unmarshal(response.body, &started))
	authorization, err := url.Parse(started.AuthorizationURL)
	require.NoError(t, err)
	require.Equal(t, "https", authorization.Scheme)
	expectedHost := "accounts.google.com"
	if name == "telegram" {
		expectedHost = "oauth.telegram.org"
	}
	require.Equal(t, expectedHost, authorization.Host)
	require.Equal(t, f.clientIDs[project][name], authorization.Query().Get("client_id"))
	require.Equal(t, web.origin+"/api/v1/auth/"+name+"/callback", authorization.Query().Get("redirect_uri"))
	code, state := f.provider.register(t, name, started.AuthorizationURL, f.secrets[project][name])
	f.projects.redisKeys[f.prefixes[project][name]+":flow:"+f.ciphers[project][name].Digest(state)] = struct{}{}
	return oidcHTTPFlow{state: state, code: code, cookie: response.cookie(t, "__Host-"+name+"-flow")}
}

func (f oidcIsolationFixture) callback(t *testing.T, ctx context.Context, project int, name string, flow oidcHTTPFlow, status int) isolationHTTPResponse {
	t.Helper()
	query := url.Values{"code": {flow.code}, "state": {flow.state}}
	response := f.webs[project].call(t, ctx, "GET", "/api/v1/auth/"+name+"/callback?"+query.Encode(), "", flow.cookie, nil)
	require.Equal(t, status, response.status, "%s", response.body)
	if status != 200 {
		require.Empty(t, response.cookies, "failed callback must not issue credentials")
	}
	return response
}

func (f oidcIsolationFixture) complete(t *testing.T, ctx context.Context, project int, name string, flow oidcHTTPFlow) oidcHTTPLogin {
	t.Helper()
	response := f.callback(t, ctx, project, name, flow, 200)
	cookie := response.cookie(t, "__Host-session")
	var me sessionhttp.MeResponse
	isolationCommand(t, ctx, f.webs[project], "GET", "/api/v1/auth/me", cookie, nil, 200, &me)
	return oidcHTTPLogin{user: me.UserID, cookie: cookie}
}

func checkOIDCProjectCallbacks(t *testing.T, ctx context.Context, f oidcIsolationFixture, name string) [2]oidcHTTPLogin {
	t.Helper()
	flows := [2]oidcHTTPFlow{f.start(t, ctx, 0, name), f.start(t, ctx, 1, name)}
	require.NotEqual(t, flows[0].state, flows[1].state)
	require.NotEqual(t, flows[0].cookie, flows[1].cookie)
	before := f.provider.requests()
	for i := range f.webs {
		f.callback(t, ctx, i, name, flows[1-i], 400)
		wrong := flows[i]
		wrong.cookie = flows[1-i].cookie
		f.callback(t, ctx, i, name, wrong, 400)
		wrong.cookie = flows[i].cookie + "; " + flows[i].cookie
		f.callback(t, ctx, i, name, wrong, 400)
		other := "google"
		if name == "google" {
			other = "telegram"
		}
		wrong.cookie = "__Host-" + other + "-flow=" + strings.SplitN(flows[i].cookie, "=", 2)[1]
		f.callback(t, ctx, i, other, wrong, 400)
	}
	require.Equal(t, before, f.provider.requests(), "state/binding/provider rejection must happen before exchange")
	wrongCode := flows[1]
	wrongCode.code = flows[0].code
	f.callback(t, ctx, 1, name, wrongCode, 400)
	flows[1] = f.start(t, ctx, 1, name)
	var logins [2]oidcHTTPLogin
	for i := range f.webs {
		logins[i] = f.complete(t, ctx, i, name, flows[i])
		require.NotEqual(t, httpIsolationUser, logins[i].user, "provider email must not merge into the password account")
		f.callback(t, ctx, i, name, flows[i], 400)
		isolationCommand(t, ctx, f.webs[1-i], "GET", "/api/v1/auth/me", logins[i].cookie, nil, 401, nil)
	}
	require.NotEqual(t, logins[0].user, logins[1].user, "same issuer+subject resolves independently in each project")
	again := f.complete(t, ctx, 0, name, f.start(t, ctx, 0, name))
	require.Equal(t, logins[0].user, again.user)
	var counts [2]int
	for i, db := range f.projects.databases {
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&counts[i]))
	}
	for i, field := range []string{"nonce", "pkce"} {
		flow := f.start(t, ctx, i, name)
		f.provider.corrupt(flow.code, field)
		f.callback(t, ctx, i, name, flow, 400)
	}
	for i, db := range f.projects.databases {
		var count int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions`).Scan(&count))
		require.Equal(t, counts[i], count, "invalid nonce/PKCE must not create a session")
	}
	return logins
}

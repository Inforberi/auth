package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	oidchttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/transport/http"
)

type identityHTTPFlow struct {
	flow    oidcHTTPFlow
	session string
}

func TestTwoProjectIdentityManagementIsolationSQL(t *testing.T) {
	if os.Getenv("AUTH_PREPARE_TEST_CATALOG_URL") == "" {
		t.Skip("requires own disposable PG/Redis and isolated provider hosts")
	}
	provider := newControlledOIDCProvider(t)
	pair := prepareHTTPProjects(t)
	projects := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	f := prepareOIDCIsolation(t, projects, provider)
	t.Cleanup(func() {
		f.webs[0].server.Close()
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		for _, db := range projects.databases {
			_, err := db.Exec(cleanup, `DELETE FROM auth.identity_audit WHERE user_id=$1`, httpIsolationUser)
			require.NoError(t, err)
			_, err = db.Exec(cleanup, `DELETE FROM auth.linked_identities WHERE user_id=$1 AND subject='isolated-oidc-subject' AND issuer IN('https://accounts.google.com','https://oauth.telegram.org')`, httpIsolationUser)
			require.NoError(t, err)
		}
	})
	for i := range projects.projects {
		projects.redisKeys[projects.passwordPrefix[i]+projects.passwordCipher[i].Digest("reauth-user:"+httpIsolationUser)] = struct{}{}
	}
	for _, name := range []string{"google", "telegram"} {
		checkProjectIdentityIsolation(t, t.Context(), f, name)
	}
}

func identityPasswordProof(t *testing.T, ctx context.Context, web isolationHTTP, cookie string) string {
	t.Helper()
	response := web.call(t, ctx, "POST", "/api/v1/auth/reauthenticate/password", web.origin, cookie, map[string]string{"password": httpIsolationPassword})
	require.Equal(t, 200, response.status, "%s", response.body)
	return response.cookie(t, "__Host-session")
}

func startIdentityLink(t *testing.T, ctx context.Context, f oidcIsolationFixture, project int, name, cookie string) identityHTTPFlow {
	t.Helper()
	web := f.webs[project]
	response := web.call(t, ctx, "POST", "/api/v1/auth/"+name+"/link", web.origin, cookie, nil)
	require.Equal(t, 200, response.status, "%s", response.body)
	var started oidchttp.StartResponse
	require.NoError(t, json.Unmarshal(response.body, &started))
	code, state := f.provider.register(t, name, started.AuthorizationURL, f.secrets[project][name])
	f.projects.redisKeys[f.prefixes[project][name]+":flow:"+f.ciphers[project][name].Digest(state)] = struct{}{}
	return identityHTTPFlow{flow: oidcHTTPFlow{state: state, code: code, cookie: response.cookie(t, "__Host-"+name+"-flow")}, session: cookie}
}

func identityLinkCallback(t *testing.T, ctx context.Context, f oidcIsolationFixture, project int, name string, proof identityHTTPFlow, status int) {
	t.Helper()
	flow := proof.flow
	if proof.session != "" {
		flow.cookie += "; " + proof.session
	}
	response := f.callback(t, ctx, project, name, flow, status)
	if status == 200 {
		require.Len(t, response.cookies, 1)
		require.Equal(t, "__Host-"+name+"-flow", response.cookies[0].Name)
		require.Empty(t, response.cookies[0].Value)
		var result oidchttp.CallbackResponse
		require.NoError(t, json.Unmarshal(response.body, &result))
		require.Equal(t, "ok", result.Status)
	}
}

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func checkOIDCProviderRevisions(t *testing.T, ctx context.Context, f oidcIsolationFixture, name string, logins [2]oidcHTTPLogin) {
	t.Helper()
	a, b := f.start(t, ctx, 0, name), f.start(t, ctx, 1, name)
	_, err := f.projects.databases[0].Exec(ctx, `UPDATE auth.provider_settings SET version=version+1 WHERE provider=$1`, name)
	require.NoError(t, err)
	before := f.provider.requests()
	f.callback(t, ctx, 0, name, a, 400)
	require.Equal(t, before, f.provider.requests(), "provider revision mismatch must fail before exchange")
	peer := f.complete(t, ctx, 1, name, b)
	require.Equal(t, logins[1].user, peer.user)
	current := f.complete(t, ctx, 0, name, f.start(t, ctx, 0, name))
	require.Equal(t, logins[0].user, current.user)
	b = f.start(t, ctx, 1, name)
	var storedSecret []byte
	require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT secret FROM auth.provider_settings WHERE provider=$1`, name).Scan(&storedSecret))
	_, err = f.projects.databases[1].Exec(ctx, `UPDATE auth.provider_settings SET secret_set=false,secret=$2,version=version+1 WHERE provider=$1`, name, f.emptySecrets[1][name])
	require.NoError(t, err)
	before = f.provider.requests()
	failed := f.callback(t, ctx, 1, name, b, 503)
	require.Contains(t, string(failed.body), `"code":"temporarily_unavailable"`)
	response := f.webs[1].call(t, ctx, "POST", "/api/v1/auth/"+name+"/start", f.webs[1].origin, "", nil)
	require.Equal(t, 503, response.status, "%s", response.body)
	require.Contains(t, string(response.body), `"code":"temporarily_unavailable"`)
	require.Equal(t, before, f.provider.requests(), "missing B secret must not use A or cached credentials")
	current = f.complete(t, ctx, 0, name, f.start(t, ctx, 0, name))
	require.Equal(t, logins[0].user, current.user)
	_, err = f.projects.databases[1].Exec(ctx, `UPDATE auth.provider_settings SET secret_set=true,secret=$2,version=version+1 WHERE provider=$1`, name, storedSecret)
	require.NoError(t, err)
	f.callback(t, ctx, 1, name, b, 400)
	peer = f.complete(t, ctx, 1, name, f.start(t, ctx, 1, name))
	require.Equal(t, logins[1].user, peer.user)
	for i, web := range f.webs {
		var me sessionhttp.MeResponse
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", logins[i].cookie, nil, 200, &me)
		require.Equal(t, logins[i].user, me.UserID)
		var identities int
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT count(*) FROM auth.linked_identities WHERE subject=$1 AND issuer=$2`, "isolated-oidc-subject", settingsdomain.ProviderIssuer(name)).Scan(&identities))
		require.Equal(t, 1, identities)
	}
}

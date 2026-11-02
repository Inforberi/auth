package projects_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkProjectIdentityIsolation(t *testing.T, ctx context.Context, f oidcIsolationFixture, name string) {
	t.Helper()
	path := "/api/v1/auth/" + name + "/link"
	var cookies [2]string
	var versions [2]int64
	for i, web := range f.webs {
		cookies[i] = identityPasswordProof(t, ctx, web, isolationSessionLogin(t, ctx, web))
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&versions[i]))
	}
	for i, web := range f.webs {
		response := web.call(t, ctx, "POST", path, "", cookies[i], nil)
		require.Equal(t, 403, response.status)
		isolationCommand(t, ctx, web, "POST", path, "", nil, 401, nil)
		isolationCommand(t, ctx, web, "POST", path, cookies[1-i], nil, 401, nil)
	}
	flows := [2]identityHTTPFlow{startIdentityLink(t, ctx, f, 0, name, cookies[0]), startIdentityLink(t, ctx, f, 1, name, cookies[1])}
	before := f.provider.requests()
	for i := range f.webs {
		identityLinkCallback(t, ctx, f, i, name, flows[1-i], 400)
	}
	missing := flows[0]
	missing.session = ""
	identityLinkCallback(t, ctx, f, 0, name, missing, 403)
	mismatch := flows[1]
	mismatch.session = cookies[0]
	identityLinkCallback(t, ctx, f, 1, name, mismatch, 403)
	other := identityPasswordProof(t, ctx, f.webs[0], isolationSessionLogin(t, ctx, f.webs[0]))
	mismatch = startIdentityLink(t, ctx, f, 0, name, cookies[0])
	mismatch.session = other
	identityLinkCallback(t, ctx, f, 0, name, mismatch, 403)
	require.Equal(t, before, f.provider.requests(), "link flow requires its original project and session before exchange")
	for i := range flows {
		flows[i] = startIdentityLink(t, ctx, f, i, name, cookies[i])
	}
	var sessionCounts [2]int
	for i, db := range f.projects.databases {
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, httpIsolationUser).Scan(&sessionCounts[i]))
	}
	// Freshness is checked again at the SQL commit after a valid provider exchange.
	_, err := f.projects.databases[0].Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, tokengenerate.New().Hash(isolationRawCookie(cookies[0])))
	require.NoError(t, err)
	before = f.provider.requests()
	identityLinkCallback(t, ctx, f, 0, name, flows[0], 403)
	require.Equal(t, before+1, f.provider.requests())
	cookies[0] = identityPasswordProof(t, ctx, f.webs[0], cookies[0])
	flows[0] = startIdentityLink(t, ctx, f, 0, name, cookies[0])
	for i := range flows {
		identityLinkCallback(t, ctx, f, i, name, flows[i], 200)
		identityLinkCallback(t, ctx, f, i, name, flows[i], 400)
		var version int64
		var sessions, users, identities int
		db := f.projects.databases[i]
		require.NoError(t, db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&version))
		require.Equal(t, versions[i], version, "link must not bump auth_version")
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1`, httpIsolationUser).Scan(&sessions))
		require.Equal(t, sessionCounts[i], sessions, "link callback must not create a session")
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.users`).Scan(&users))
		require.Equal(t, 1, users, "link must not register another account")
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.linked_identities WHERE user_id=$1 AND issuer=$2 AND subject=$3`, httpIsolationUser, settingsdomain.ProviderIssuer(name), "isolated-oidc-subject").Scan(&identities))
		require.Equal(t, 1, identities)
	}
	for i, web := range f.webs {
		isolationCommand(t, ctx, web, "DELETE", path, cookies[1-i], nil, 401, nil)
	}
	response := f.webs[0].call(t, ctx, "DELETE", path, f.webs[0].origin, cookies[0], nil)
	require.Equal(t, 204, response.status, "%s", response.body)
	require.Len(t, response.cookies, 1)
	require.Equal(t, "__Host-session", response.cookies[0].Name)
	require.Empty(t, response.cookies[0].Value)
	for _, cookie := range []string{cookies[0], other} {
		isolationCommand(t, ctx, f.webs[0], "GET", "/api/v1/auth/me", cookie, nil, 401, nil)
	}
	isolationCommand(t, ctx, f.webs[1], "GET", "/api/v1/auth/me", cookies[1], nil, 200, nil)
	for i, db := range f.projects.databases {
		var version int64
		var identities int
		require.NoError(t, db.QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&version))
		expectedVersion := versions[i]
		expectedIdentities := 1
		if i == 0 {
			expectedVersion++
			expectedIdentities = 0
		}
		require.Equal(t, expectedVersion, version)
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.linked_identities WHERE user_id=$1 AND issuer=$2`, httpIsolationUser, settingsdomain.ProviderIssuer(name)).Scan(&identities))
		require.Equal(t, expectedIdentities, identities, "unlink A must preserve B's identity")
	}
}

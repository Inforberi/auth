package main

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestTwoProjectDependencyRecoverySQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	webs, _ := serveRecoveryProjects(t, f)
	ctx := t.Context()
	cookies := [2]string{isolationSessionLogin(t, ctx, webs[0]), isolationSessionLogin(t, ctx, webs[1])}
	const me = "/api/v1/auth/me"
	// Remove one real SQL permission; an unavailable project must not fall back to B.
	var role string
	require.NoError(t, pair.admin.QueryRow(ctx, `SELECT rolname FROM pg_roles WHERE oid=$1`, pair.a.Binding.RuntimeOID).Scan(&role))
	restoreProject := revokeIsolationSelect(t, f.databases[0], "auth", "sessions", role)
	response := webs[0].call(t, ctx, "GET", me, "", cookies[0], nil)
	require.Equal(t, 503, response.status, "%s", response.body)
	require.NotContains(t, string(response.body), "permission denied")
	require.Empty(t, response.cookies)
	isolationCommand(t, ctx, webs[1], "GET", me, cookies[1], nil, 200, nil)
	restoreProject()
	isolationCommand(t, ctx, webs[0], "GET", me, cookies[0], nil, 200, nil)
	// The shared catalog is authority even while both HTTP profiles remain warm.
	restoreCatalog := revokeIsolationSelect(t, pair.admin, "platform", "projects", "auth_platform_runtime_reader_test")
	for i, web := range webs {
		response = web.call(t, ctx, "GET", me, "", cookies[i], nil)
		require.Equal(t, 503, response.status, "%s", response.body)
		require.NotContains(t, string(response.body), "permission denied")
		require.Empty(t, response.cookies)
	}
	restoreCatalog()
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", me, cookies[i], nil, 200, nil)
	}
	// This is an injected command failure on the existing client, not a network partition.
	fault := new(isolationRedisFault)
	f.deps.Redis.AddHook(fault)
	t.Cleanup(func() { fault.failed.Store(false) })
	fault.failed.Store(true)
	login := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	for _, web := range webs {
		response = web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", login)
		require.Equal(t, 503, response.status, "%s", response.body)
		require.Empty(t, response.cookies)
		require.NotContains(t, string(response.body), errIsolationRedisUnavailable.Error())
	}
	fault.failed.Store(false)
	for i, web := range webs {
		fresh := isolationSessionLogin(t, ctx, web)
		isolationCommand(t, ctx, web, "GET", me, fresh, nil, 200, nil)
		isolationCommand(t, ctx, web, "GET", me, cookies[1-i], nil, 401, nil)
		var status string
		require.NoError(t, f.databases[i].QueryRow(ctx, `SELECT status FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&status))
		require.Equal(t, "active", status)
	}
}

func revokeIsolationSelect(t *testing.T, db *pgx.Conn, schema, table, role string) func() {
	t.Helper()
	name := pgx.Identifier{schema, table}.Sanitize()
	user := pgx.Identifier{role}.Sanitize()
	var allowed bool
	require.NoError(t, db.QueryRow(t.Context(), `SELECT has_table_privilege($1,$2,'SELECT')`, role, name).Scan(&allowed))
	require.True(t, allowed, "fault injection must restore an existing grant only")
	restored := false
	restore := func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		_, err := db.Exec(ctx, "GRANT SELECT ON "+name+" TO "+user)
		require.NoError(t, err)
		restored = true
	}
	t.Cleanup(restore)
	_, err := db.Exec(t.Context(), "REVOKE SELECT ON "+name+" FROM "+user)
	require.NoError(t, err)
	return restore
}

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func checkProjectSettingsIsolation(t *testing.T, ctx context.Context, f projectIsolationHTTP, webs [2]isolationHTTP) {
	t.Helper()
	const path = "/api/v1/admin/auth/settings"
	owners := [2]string{isolationAdminLogin(t, ctx, webs[0], httpOwnerEmail), isolationAdminLogin(t, ctx, webs[1], httpOwnerEmail)}
	var before [2]settingshttp.SettingsResponse
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", path, owners[1-i], nil, 401, nil)
		isolationCommand(t, ctx, web, "GET", path, owners[i], nil, 200, &before[i])
	}
	require.Equal(t, before[0].Version, before[1].Version, "identical fixture revisions must diverge independently")
	var peerBefore string
	const peerState = `SELECT jsonb_build_object('policy',(SELECT to_jsonb(p) FROM auth.auth_settings p),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM auth.auth_settings_audit a))::text`
	require.NoError(t, f.databases[1].QueryRow(ctx, peerState).Scan(&peerBefore))
	changedPolicy := before[0].Policy
	changedPolicy.Registration.Enabled = true
	request := map[string]any{"expectedVersion": before[0].Version, "policy": changedPolicy}
	isolationCommand(t, ctx, webs[1], "POST", path, owners[0], request, 401, nil)
	var changed settingshttp.SettingsResponse
	isolationCommand(t, ctx, webs[0], "POST", path, owners[0], request, 200, &changed)
	require.Equal(t, before[0].Version+1, changed.Version)
	// The resident route snapshot detects its changed policy, then rebuilds on the next request.
	isolationCommand(t, ctx, webs[0], "GET", path, owners[0], nil, 404, nil)
	var current settingshttp.SettingsResponse
	isolationCommand(t, ctx, webs[0], "GET", path, owners[0], nil, 200, &current)
	require.True(t, current.Policy.Registration.Enabled)
	isolationCommand(t, ctx, webs[0], "POST", path, owners[0], request, 409, nil)
	isolationCommand(t, ctx, webs[1], "POST", path, owners[1], map[string]any{"expectedVersion": changed.Version, "policy": changedPolicy}, 409, nil)
	var peer settingshttp.SettingsResponse
	isolationCommand(t, ctx, webs[1], "GET", path, owners[1], nil, 200, &peer)
	require.Equal(t, before[1].Version, peer.Version)
	require.Equal(t, before[1].Policy, peer.Policy)
	// A valid B no-op uses its own version and must not create an audit row.
	isolationCommand(t, ctx, webs[1], "POST", path, owners[1], map[string]any{"expectedVersion": peer.Version, "policy": peer.Policy}, 200, nil)
	var peerAfter string
	require.NoError(t, f.databases[1].QueryRow(ctx, peerState).Scan(&peerAfter))
	require.Equal(t, peerBefore, peerAfter)
}

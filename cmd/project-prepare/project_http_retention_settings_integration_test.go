package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func (f projectAccountFixture) httpRetentionSettings(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken, ordinaryToken string) {
	t.Helper()
	const actor = "f8300000-0000-4000-8000-000000000001"
	const path = "/api/v1/admin/auth/settings/retention"
	_, err := f.db.Exec(ctx, `CREATE TEMP TABLE retention_http_before AS TABLE auth.retention_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.retention_settings_audit WHERE actor_id=$1;
 DELETE FROM auth.retention_settings; INSERT INTO auth.retention_settings SELECT * FROM retention_http_before`, actor)
		require.NoError(t, err)
	})
	_, err = f.db.Exec(ctx, `INSERT INTO auth.retention_settings(singleton,email_reservation_days,session_days,security_audit_days)
 VALUES(true,30,30,180) ON CONFLICT(singleton) DO NOTHING`)
	require.NoError(t, err)
	read := func(cookie string, expected int) settingshttp.RetentionResponse {
		t.Helper()
		status, cookies, body := web("GET", path, origin, cookie, "")
		require.Equal(t, expected, status, "%s", body)
		require.Empty(t, cookies)
		var response settingshttp.RetentionResponse
		if expected == 200 {
			require.NoError(t, json.Unmarshal(body, &response))
		}
		return response
	}
	read("", 401)
	read(ordinaryToken, 403)
	before := read(actorToken, 200)
	var sessionBefore, sessionAfter string
	require.NoError(t, f.db.QueryRow(ctx, `SELECT row_to_json(s)::text FROM auth.sessions s WHERE user_id=$1`, actor).Scan(&sessionBefore))
	policy := before.Policy
	input := settingshttp.RetentionUpdateRequest{ExpectedVersion: before.Version, Policy: &policy}
	web.command(t, path, "https://foreign.example.test", actorToken, input, 403, nil)
	web.command(t, path, origin, ordinaryToken, input, 403, nil)
	var changed settingshttp.RetentionResponse
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before, changed, "no-op must preserve version")
	policy.SessionDays = 106752
	web.command(t, path, origin, actorToken, input, 400, nil)
	policy.SessionDays = before.Policy.SessionDays + 1
	require.LessOrEqual(t, policy.SessionDays, 106751)
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before.Version+1, changed.Version)
	require.Equal(t, policy, changed.Policy)
	web.command(t, path, origin, actorToken, input, 409, nil)
	input.ExpectedVersion = changed.Version
	policy = before.Policy
	body := web.commandMethod(t, "POST", path, origin, actorToken, input, 409, nil)
	require.Contains(t, string(body), "retention_confirmation_required")
	input.ConfirmShortening = true
	web.command(t, path, origin, actorToken, input, 200, &changed)
	require.Equal(t, before.Version+2, changed.Version)
	require.Equal(t, before.Policy, changed.Policy)
	require.Equal(t, changed, read(actorToken, 200))
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.retention_settings_audit WHERE actor_id=$1`, actor).Scan(&audits))
	require.Equal(t, 2, audits, "no-op, rejected and stale updates must not add audits")
	require.NoError(t, f.db.QueryRow(ctx, `SELECT row_to_json(s)::text FROM auth.sessions s WHERE user_id=$1`, actor).Scan(&sessionAfter))
	require.Equal(t, sessionBefore, sessionAfter, "settings calls must not refresh the session")
	_, err = f.db.Exec(ctx, `DELETE FROM auth.retention_settings`)
	require.NoError(t, err)
	read(actorToken, 403)
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.retention_settings`).Scan(&audits))
	require.Zero(t, audits, "GET must not initialize settings from ENV")
}

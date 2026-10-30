package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (f projectAccountFixture) httpMFASettings(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken string) {
	t.Helper()
	const actor = "f8300000-0000-4000-8000-000000000001"
	const ordinary = "f8900000-0000-4000-8000-000000000001"
	const path = "/api/v1/admin/auth/settings/mfa"
	tokens := tokengenerate.New()
	ordinaryToken, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, ordinary)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id=$1`, ordinary)
		require.NoError(t, err)
		_, err = f.db.Exec(cleanup, `DELETE FROM auth.users WHERE id=$1`, ordinary)
		require.NoError(t, err)
	})
	// A live ordinary session isolates permission denial from earlier account-flow revocations.
	_, err = f.db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,password_verified_at,user_agent,ip_address)
 SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),clock_timestamp(),'MFA policy ordinary fixture','192.0.2.89'
 FROM auth.users WHERE id=$2`, tokens.Hash(ordinaryToken), ordinary)
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `CREATE TEMP TABLE mfa_http_before AS TABLE auth.mfa_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor)
		require.NoError(t, err)
		_, err = f.db.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=(SELECT mode FROM mfa_http_before) WHERE singleton`)
		require.NoError(t, err)
	})
	var platformMode string
	var platformVersion, platformRevision int64
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT mode,version,session_revision FROM auth.mfa_settings WHERE singleton`).Scan(&platformMode, &platformVersion, &platformRevision))
	read := func(raw string, status int) settingshttp.MFASettingsResponse {
		t.Helper()
		code, cookies, body := web("GET", path, origin, raw, "")
		require.Equal(t, status, code, "%s", body)
		require.Empty(t, cookies)
		var result settingshttp.MFASettingsResponse
		if status == 200 {
			require.NoError(t, json.Unmarshal(body, &result))
		}
		return result
	}
	// The preceding Auth settings fixture restored its policy; evict that stale route plan first.
	read(actorToken, 404)
	read("", 401)
	read(ordinaryToken, 403)
	before := read(actorToken, 200)
	input := settingshttp.MFAUpdateRequest{ExpectedVersion: before.Version, Policy: &before.Policy}
	web.command(t, path, "https://foreign.example.test", actorToken, input, 403, nil)
	web.command(t, path, origin, "", input, 401, nil)
	web.command(t, path, origin, ordinaryToken, input, 403, nil)
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "invalid"}
	web.command(t, path, origin, actorToken, input, 400, nil)
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "optional"}
	var optional settingshttp.MFASettingsResponse
	web.command(t, path, origin, actorToken, input, 200, &optional)
	require.Equal(t, before.Version+1, optional.Version)
	web.command(t, path, origin, actorToken, input, 409, nil)
	input.ExpectedVersion = optional.Version
	web.command(t, path, origin, actorToken, input, 200, nil)
	var factors int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_totp WHERE user_id=$1`, actor).Scan(&factors))
	require.Equal(t, 1, factors, "weakening must preserve the personal factor")
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "required"}
	var required settingshttp.MFASettingsResponse
	web.command(t, path, origin, actorToken, input, 200, &required)
	require.Equal(t, optional.Version+1, required.Version)
	read(actorToken, 401)
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor).Scan(&audits))
	require.Equal(t, 2, audits, "denied/no-op requests must not create audit rows")
	var unchanged bool
	require.NoError(t, f.admin.QueryRow(ctx, `SELECT mode=$1 AND version=$2 AND session_revision=$3 FROM auth.mfa_settings WHERE singleton`, platformMode, platformVersion, platformRevision).Scan(&unchanged))
	require.True(t, unchanged, "project HTTP must not change platform policy")
}

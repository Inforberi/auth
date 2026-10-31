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

func (f projectAccountFixture) httpAuthSettings(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken string) {
	t.Helper()
	const actor = "f8300000-0000-4000-8000-000000000001"
	const administrator = "f8800000-0000-4000-8000-000000000001"
	tokens := tokengenerate.New()
	stale, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `CREATE TEMP TABLE settings_http_before AS TABLE auth.auth_settings;
 INSERT INTO auth.users(id) VALUES($1);
 INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Settings fixture super administrator',true);
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'access.assignments.manage' FROM auth.roles WHERE key='super_admin';
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='super_admin';
 INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,'settings-admin@example.test',clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash)
 SELECT $1,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$1 AND p.user_id=$2::uuid;
 INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$3,0);
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 SELECT $4,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),clock_timestamp(),'totp','settings-fixture','192.0.2.88' FROM auth.users WHERE id=$5`, administrator, f.sourceUser, make([]byte, 48), tokens.Hash(stale), actor)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.auth_settings_audit WHERE actor_id=$1;
 DELETE FROM auth.sessions WHERE token_hash=$3;
 DELETE FROM auth.user_roles WHERE user_id=$2;
 DELETE FROM auth.users WHERE id=$2;
 DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key='super_admin');
 DELETE FROM auth.roles WHERE key='super_admin';
 DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM settings_http_before`, actor, administrator, tokens.Hash(stale))
		require.NoError(t, err)
	})
	const path = "/api/v1/admin/auth/settings"
	read := func(cookie string, expected int) settingshttp.SettingsResponse {
		t.Helper()
		status, cookies, body := web("GET", path, origin, cookie, "")
		require.Equal(t, expected, status, "%s", body)
		require.Empty(t, cookies)
		var result settingshttp.SettingsResponse
		if expected == 200 {
			require.NoError(t, json.Unmarshal(body, &result))
		}
		return result
	}
	read("", 401)
	before := read(actorToken, 200)
	require.NotNil(t, before.Readiness)
	require.Equal(t, before.Version, before.Readiness.PolicyVersion)
	request := func(version int64, policy settingshttp.PolicyResponse) map[string]any {
		return map[string]any{"expectedVersion": version, "policy": policy}
	}
	web.command(t, path, "https://foreign.example.test", actorToken, request(before.Version, before.Policy), 403, nil)
	web.command(t, path, origin, "", request(before.Version, before.Policy), 401, nil)
	web.command(t, path, origin, stale, request(before.Version, before.Policy), 403, nil)
	web.command(t, path, origin, actorToken, request(0, before.Policy), 400, nil)
	unavailable := before.Policy
	unavailable.Methods.Google = true
	body := web.commandMethod(t, "POST", path, origin, actorToken, request(before.Version, unavailable), 409, nil)
	require.Contains(t, string(body), `"code":"auth_method_not_ready"`)
	unavailable = before.Policy
	unavailable.PasswordEmailVerification = "required"
	body = web.commandMethod(t, "POST", path, origin, actorToken, request(before.Version, unavailable), 409, nil)
	require.Contains(t, string(body), `"code":"auth_method_not_ready"`)
	disabled := before.Policy
	disabled.Methods.Password, disabled.Registration.Enabled = false, false
	var changed settingshttp.SettingsResponse
	web.command(t, path, origin, actorToken, request(before.Version, disabled), 200, &changed)
	require.Equal(t, before.Version+1, changed.Version)
	require.NotNil(t, changed.Readiness)
	require.Equal(t, before.Version, changed.Readiness.PolicyVersion, "write returns the observation used for admission")
	read(actorToken, 404)
	current := read(actorToken, 200)
	require.False(t, current.Policy.Methods.Password)
	require.True(t, current.AvailableMethods.Password, "deployment remains capable of re-enabling password login")
	web.command(t, path, origin, actorToken, request(before.Version, before.Policy), 409, nil)
	web.command(t, path, origin, actorToken, request(current.Version, before.Policy), 200, &changed)
	require.Equal(t, before.Version+2, changed.Version)
	read(actorToken, 404)
	current = read(actorToken, 200)
	web.command(t, path, origin, actorToken, request(current.Version, current.Policy), 200, &changed)
	require.Equal(t, current.Version, changed.Version)
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT count(*) FROM auth.auth_settings_audit WHERE actor_id=$1`, actor).Scan(&audits))
	require.Equal(t, 2, audits, "failed and no-op updates must not repeat the mutation")
}

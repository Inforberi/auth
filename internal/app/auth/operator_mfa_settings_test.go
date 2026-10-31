package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

func operatorMFASettingsDrill(t *testing.T, admin *pgxpool.Pool, h *operatorHTTPS, actor operatordomain.Principal) {
	t.Helper()
	ctx := t.Context()
	client := *h
	client.t = t
	h = &client
	const path = "/api/v1/platform/settings/mfa"
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	actor.TokenHash = tokens.Hash(raw)
	// A synthetic completed password/MFA proof belongs only to this final HTTP scenario.
	_, err = admin.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),clock_timestamp(),clock_timestamp(),'totp','MFA settings fixture','192.0.2.90'
 FROM auth.users WHERE id=$2`, actor.TokenHash, actor.UserID)
	require.NoError(t, err)
	cookies := []*http.Cookie{{Name: sessionhttp.SessionCookieName, Value: raw}}
	var beforeMode string
	err = admin.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings WHERE singleton`).Scan(&beforeMode)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `DELETE FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor.UserID)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=$1 WHERE singleton`, beforeMode)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM auth.sessions WHERE token_hash=$1`, actor.TokenHash)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2) ON CONFLICT DO NOTHING`, actor.UserID, operatordomain.SettingsManage)
		require.NoError(t, err)
	})
	h.call("GET", path, nil, nil, 401)
	before, _ := h.call("GET", path, nil, cookies, 200)
	var version int64
	require.NoError(t, json.Unmarshal(before["version"], &version))
	var policy settingshttp.MFAPolicyDTO
	require.NoError(t, json.Unmarshal(before["policy"], &policy))
	input := settingshttp.MFAUpdateRequest{ExpectedVersion: version, Policy: &policy}
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2`, actor.UserID, operatordomain.SettingsManage)
	require.NoError(t, err)
	h.call("GET", path, nil, cookies, 403)
	h.call("POST", path, input, cookies, 403)
	_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,$2)`, actor.UserID, operatordomain.SettingsManage)
	require.NoError(t, err)
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "invalid"}
	h.call("POST", path, input, cookies, 400)
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "optional"}
	optional, issued := h.call("POST", path, input, cookies, 200)
	require.Empty(t, issued)
	var next int64
	require.NoError(t, json.Unmarshal(optional["version"], &next))
	require.Equal(t, version+1, next)
	h.call("POST", path, input, cookies, 409)
	input.ExpectedVersion = next
	h.call("POST", path, input, cookies, 200)
	input.Policy = &settingshttp.MFAPolicyDTO{Mode: "required"}
	_, issued = h.call("POST", path, input, cookies, 200)
	require.Empty(t, issued)
	h.call("GET", path, nil, cookies, 401)
	var audits int
	require.NoError(t, admin.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_settings_audit WHERE actor_id=$1`, actor.UserID).Scan(&audits))
	require.Equal(t, 2, audits)
}

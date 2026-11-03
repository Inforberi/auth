package projects_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pgx "github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	mfaloginhttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
)

func checkProjectHTTPIsolation(t *testing.T, ctx context.Context, admin *pgx.Conn, databases [2]*pgx.Conn, key projectruntime.Key, webs [2]isolationHTTP, handler http.Handler) {
	t.Helper()
	a, b := webs[0], webs[1]
	const loginPath = "/api/v1/auth/login/email"
	const mePath = "/api/v1/auth/me"
	const enrollPath = "/api/v1/auth/mfa/login/enrollment"
	const confirmPath = "/api/v1/auth/mfa/login/enrollment/confirm"
	const completePath = "/api/v1/auth/mfa/login/complete"
	login := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	var platformBefore string
	const platformState = `SELECT jsonb_build_object(
 'mfa',(SELECT to_jsonb(p) FROM auth.mfa_settings p),
 'auth',(SELECT to_jsonb(p) FROM auth.auth_settings p),
 'realm',(SELECT to_jsonb(r) FROM platform.operator_realm r),
 'authority',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.user_id,p.permission_key) FROM platform.operator_permissions p),
 'sessions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id) FROM auth.sessions s))::text`
	require.NoError(t, admin.QueryRow(ctx, platformState).Scan(&platformBefore))
	for _, web := range webs {
		require.Equal(t, 403, web.call(t, ctx, "POST", loginPath, "", "", login).status)
		require.Equal(t, 403, web.call(t, ctx, "POST", loginPath, "https://foreign.example.test", "", login).status)
	}
	aLogin := a.call(t, ctx, "POST", loginPath, a.origin, "", login)
	bLogin := b.call(t, ctx, "POST", loginPath, b.origin, "", login)
	require.Equal(t, 200, aLogin.status, "%s", aLogin.body)
	require.Equal(t, 200, bLogin.status, "%s", bLogin.body)
	cookieA, cookieB := aLogin.cookie(t, "__Host-session"), bLogin.cookie(t, "__Host-session")
	require.Equal(t, 403, b.call(t, ctx, "POST", "/api/v1/auth/logout", "", cookieB, nil).status)
	require.Equal(t, 403, b.call(t, ctx, "POST", "/api/v1/auth/logout", a.origin, cookieB, nil).status)
	for _, pair := range []struct {
		web            isolationHTTP
		local, foreign string
	}{{a, cookieA, cookieB}, {b, cookieB, cookieA}} {
		require.Equal(t, 200, pair.web.call(t, ctx, "GET", mePath, "", pair.local, nil).status)
		require.Equal(t, 401, pair.web.call(t, ctx, "GET", mePath, "", pair.foreign, nil).status)
	}
	spoof := http.Header{"X-Project-ID": []string{string(key.Binding.ProjectID)}, "X-Forwarded-Host": []string{"test.example.test"}, "X-Forwarded-Proto": []string{"https"}}
	require.Equal(t, 200, b.call(t, ctx, "GET", mePath, b.origin, cookieB, nil, spoof).status)
	require.Equal(t, 401, b.call(t, ctx, "GET", mePath, b.origin, cookieA, nil, spoof).status)
	require.Equal(t, 403, a.call(t, ctx, "POST", loginPath, b.origin, cookieB, login, spoof).status)
	require.Equal(t, 403, b.call(t, ctx, "OPTIONS", loginPath, a.origin, "", nil, http.Header{"Access-Control-Request-Method": []string{"POST"}}).status)
	unknown := isolationHTTP{server: a.server, origin: "https://unknown.example.test"}
	require.Equal(t, 404, unknown.call(t, ctx, "GET", mePath, "", cookieA, nil, spoof).status)
	platform := isolationHTTP{server: a.server, origin: "https://platform-http.example.test"}
	require.Equal(t, 404, platform.call(t, ctx, "GET", mePath, "", cookieA, nil).status)
	plain := httptest.NewServer(handler)
	t.Cleanup(plain.Close)
	plaintext := isolationHTTP{server: plain, origin: a.origin}
	require.Equal(t, 404, plaintext.call(t, ctx, "GET", mePath, "", cookieA, nil, spoof).status)
	_, err := databases[0].Exec(ctx, `UPDATE auth.roles SET mfa_required=true,version=version+1,session_revision=session_revision+1 WHERE key='http_isolation_mfa'`)
	require.NoError(t, err)
	require.Equal(t, 401, a.call(t, ctx, "GET", mePath, "", cookieA, nil).status)
	require.Equal(t, 200, b.call(t, ctx, "GET", mePath, "", cookieB, nil).status)
	limited := a.call(t, ctx, "POST", loginPath, a.origin, "", login)
	require.Equal(t, 202, limited.status, "%s", limited.body)
	var challenge mfaloginhttp.ChallengeResponse
	require.NoError(t, json.Unmarshal(limited.body, &challenge))
	require.Equal(t, "mfa_enrollment_required", challenge.Status)
	binding := limited.cookie(t, mfaloginhttp.LoginCookie)
	start := mfaloginhttp.LoginEnrollmentRequest{Challenge: challenge.Challenge}
	require.Equal(t, 401, b.call(t, ctx, "GET", mePath, "", binding, nil).status)
	require.Equal(t, 400, b.call(t, ctx, "POST", enrollPath, b.origin, binding, start).status)
	require.Equal(t, 403, a.call(t, ctx, "POST", enrollPath, b.origin, binding, start).status)
	require.Equal(t, 400, a.call(t, ctx, "POST", enrollPath, a.origin, "", start).status)
	enrolled := a.call(t, ctx, "POST", enrollPath, a.origin, binding, start)
	require.Equal(t, 200, enrolled.status, "%s", enrolled.body)
	var enrollment mfahttp.EnrollmentResponse
	require.NoError(t, json.Unmarshal(enrolled.body, &enrollment))
	confirmation := mfaloginhttp.ConfirmLoginEnrollmentRequest{Challenge: challenge.Challenge, Token: enrollment.Token, Code: projectMFACode(t, ctx, databases[0], enrollment.Secret, 0)}
	require.Equal(t, 400, b.call(t, ctx, "POST", confirmPath, b.origin, binding, confirmation).status)
	confirmed := a.call(t, ctx, "POST", confirmPath, a.origin, binding, confirmation)
	require.Equal(t, 200, confirmed.status, "%s", confirmed.body)
	var codes mfahttp.RecoveryCodesResponse
	require.NoError(t, json.Unmarshal(confirmed.body, &codes))
	require.Len(t, codes.Codes, 10)
	for _, cookie := range confirmed.cookies {
		require.False(t, cookie.Name == "__Host-session" && cookie.Value != "" && cookie.MaxAge >= 0)
	}
	limited = a.call(t, ctx, "POST", loginPath, a.origin, "", login)
	require.Equal(t, 202, limited.status)
	require.NoError(t, json.Unmarshal(limited.body, &challenge))
	binding = limited.cookie(t, mfaloginhttp.LoginCookie)
	completion := mfaloginhttp.CompleteLoginRequest{Challenge: challenge.Challenge, Code: codes.Codes[0], Recovery: true}
	require.Equal(t, 400, b.call(t, ctx, "POST", completePath, b.origin, binding, completion).status)
	completed := a.call(t, ctx, "POST", completePath, a.origin, binding, completion)
	require.Equal(t, 200, completed.status, "%s", completed.body)
	cookieA = completed.cookie(t, "__Host-session")
	require.Equal(t, 200, a.call(t, ctx, "GET", mePath, "", cookieA, nil).status)
	require.Equal(t, 401, b.call(t, ctx, "GET", mePath, "", cookieA, nil).status)
	require.Equal(t, 200, b.call(t, ctx, "GET", mePath, "", cookieB, nil).status)
	limited = a.call(t, ctx, "POST", loginPath, a.origin, "", login)
	require.Equal(t, 202, limited.status)
	require.NoError(t, json.Unmarshal(limited.body, &challenge))
	binding = limited.cookie(t, mfaloginhttp.LoginCookie)
	completion.Challenge, completion.Code = challenge.Challenge, codes.Codes[1]
	t.Cleanup(func() {
		_, err := admin.Exec(context.WithoutCancel(ctx), `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, key.Binding.ProjectID)
		require.NoError(t, err)
	})
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, key.Binding.ProjectID)
	require.NoError(t, err)
	require.Equal(t, 404, a.call(t, ctx, "GET", mePath, "", cookieA, nil).status)
	require.Equal(t, 404, a.call(t, ctx, "POST", completePath, a.origin, binding, completion).status)
	require.Equal(t, 200, b.call(t, ctx, "GET", mePath, "", cookieB, nil).status)
	require.Equal(t, 200, b.call(t, ctx, "POST", loginPath, b.origin, "", login).status)
	var peerSafe bool
	require.NoError(t, databases[1].QueryRow(ctx, `SELECT auth_version=1
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_login_challenges WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.roles WHERE key='http_isolation_mfa' AND mfa_required)
 FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&peerSafe))
	require.True(t, peerSafe)
	var platformAfter string
	require.NoError(t, admin.QueryRow(ctx, platformState).Scan(&platformAfter))
	require.Equal(t, platformBefore, platformAfter)
}

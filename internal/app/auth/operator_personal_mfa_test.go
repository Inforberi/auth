package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func operatorPersonalMFADrill(t *testing.T, admin *pgxpool.Pool, deps realmDependencies, cfg *config.Config, h *operatorHTTPS, user accountdomain.UserID) {
	t.Helper()
	ctx := t.Context()
	client := *h
	client.t = t
	h = &client
	cipher, err := (realmSecurity{scope: deps.scope}).cipher(cfg.Account.EncryptionKey, "mfa:v1")
	require.NoError(t, err)
	prefix, err := deps.scope.RedisPrefix("mfa-limit", "auth:mfa:limit:")
	require.NoError(t, err)
	// DB15 belongs to this fixture. Start a new scenario without prior login-factor attempts.
	require.NoError(t, deps.redis.Del(ctx, prefix+cipher.Digest("login:factor-user:"+string(user))).Err())
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	digest := tokens.Hash(raw)
	// The initial strong session is synthetic; all subsequent login/enrollment/step-up uses HTTP.
	_, err = admin.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),clock_timestamp(),clock_timestamp(),'totp','personal MFA fixture','192.0.2.91'
 FROM auth.users WHERE id=$2`, digest, user)
	require.NoError(t, err)
	cookies := []*http.Cookie{{Name: sessionhttp.SessionCookieName, Value: raw}}
	var originalMode string
	require.NoError(t, admin.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings WHERE singleton`).Scan(&originalMode))
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=$1 WHERE singleton`, originalMode)
		require.NoError(t, err)
	})
	const factorPath = "/api/v1/auth/mfa/totp"
	const policyPath = "/api/v1/platform/settings/mfa"
	h.call("DELETE", factorPath, nil, nil, 401)
	status, _ := h.call("GET", "/api/v1/auth/mfa/status", nil, cookies, 200)
	require.Equal(t, "true", string(status["requiredByPolicy"]))
	denied, _ := h.call("DELETE", factorPath, nil, cookies, 403)
	require.Equal(t, "mfa_required_by_policy", operatorField(t, denied, "code"))
	policy, _ := h.call("GET", policyPath, nil, cookies, 200)
	var version int64
	require.NoError(t, json.Unmarshal(policy["version"], &version))
	optional, _ := h.call("POST", policyPath, map[string]any{"expectedVersion": version, "policy": map[string]string{"mode": "optional"}}, cookies, 200)
	require.NoError(t, json.Unmarshal(optional["version"], &version))
	status, _ = h.call("GET", "/api/v1/auth/mfa/status", nil, cookies, 200)
	require.Equal(t, "true", string(status["disableAllowedByPolicy"]))
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, digest)
	require.NoError(t, err)
	h.call("DELETE", factorPath, nil, cookies, 403)
	_, err = admin.Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp(),
 primary_verified_at=clock_timestamp()-interval '11 minutes',mfa_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, digest)
	require.NoError(t, err)
	h.call("DELETE", factorPath, nil, cookies, 403)
	code := strings.Repeat("a", 32)
	_, err = admin.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) VALUES($1,$2)`, user, cipher.Digest("recovery:"+string(user)+":"+code))
	require.NoError(t, err)
	_, issued := h.call("POST", "/api/v1/auth/mfa/step-up", map[string]any{"code": code, "recovery": true}, cookies, 200)
	old := cookies
	cookies = []*http.Cookie{operatorCookie(t, issued, sessionhttp.SessionCookieName)}
	h.call("GET", "/api/v1/auth/me", nil, old, 401)
	h.call("POST", "/api/v1/auth/mfa/step-up", map[string]any{"code": code, "recovery": true}, cookies, 400)
	_, cleared := h.call("DELETE", factorPath, nil, cookies, 200)
	deleted := false
	for _, cookie := range cleared {
		if cookie.Name == sessionhttp.SessionCookieName && cookie.MaxAge < 0 {
			deleted = true
		}
	}
	require.True(t, deleted, "disable must clear the verifier cookie")
	h.call("GET", "/api/v1/auth/me", nil, cookies, 401)
	var noFactor bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.mfa_recovery_codes WHERE user_id=$1)
 AND NOT EXISTS(SELECT 1 FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL)`, user).Scan(&noFactor))
	require.True(t, noFactor)
	// operatorRecoveryDrill replaced the initial password before this scenario.
	password := "EmergencyPassword3"
	if os.Getenv("AUTH_OPERATOR_TEST_CLI") != "" {
		password = "PlatformClilogin4"
	}
	credentials := map[string]string{"email": "operator@example.test", "password": password}
	_, issued = h.call("POST", "/api/v1/admin/auth/login/email", credentials, nil, 200)
	cookies = []*http.Cookie{operatorCookie(t, issued, sessionhttp.SessionCookieName)}
	h.call("POST", factorPath+"/enrollment", nil, cookies, 200)
	h.call("POST", policyPath, map[string]any{"expectedVersion": version, "policy": map[string]string{"mode": "required"}}, cookies, 200)
	h.call("GET", "/api/v1/auth/me", nil, cookies, 401)
	challenge, issued := h.call("POST", "/api/v1/admin/auth/login/email", credentials, nil, 202)
	require.Equal(t, "mfa_enrollment_required", operatorField(t, challenge, "status"))
	bound := []*http.Cookie{operatorCookie(t, issued, "__Host-mfa-login")}
	h.call("GET", "/api/v1/auth/me", nil, bound, 401)
	challengeToken := operatorField(t, challenge, "challenge")
	enrollment, _ := h.call("POST", "/api/v1/auth/mfa/login/enrollment", map[string]string{"challenge": challengeToken}, bound, 200)
	var now time.Time
	require.NoError(t, admin.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now))
	totpCode, err := totp.GenerateCode(operatorField(t, enrollment, "secret"), now)
	require.NoError(t, err)
	confirmed, _ := h.call("POST", "/api/v1/auth/mfa/login/enrollment/confirm", map[string]string{"challenge": challengeToken, "token": operatorField(t, enrollment, "token"), "code": totpCode}, bound, 200)
	var codes []string
	require.NoError(t, json.Unmarshal(confirmed["codes"], &codes))
	require.Len(t, codes, 10)
	h.call("GET", "/api/v1/auth/me", nil, bound, 401)
	challenge, issued = h.call("POST", "/api/v1/admin/auth/login/email", credentials, nil, 202)
	bound = []*http.Cookie{operatorCookie(t, issued, "__Host-mfa-login")}
	_, issued = h.call("POST", "/api/v1/auth/mfa/login/complete", map[string]any{"challenge": operatorField(t, challenge, "challenge"), "code": codes[0], "recovery": true}, bound, 200)
	cookies = []*http.Cookie{operatorCookie(t, issued, sessionhttp.SessionCookieName)}
	h.call("GET", "/api/v1/auth/me", nil, cookies, 200)
	h.call("DELETE", factorPath, nil, cookies, 403)
}

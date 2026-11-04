package projects_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	profileapp "github.com/Inforberi/financial-intelligence/internal/app/projects/profile"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/transport/http"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/native/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestTwoProjectEmailMFAHTTP(t *testing.T) {
	f := prepareEmailMFAHTTP(t)
	ctx := t.Context()
	web := f.webs[0]
	owner := isolationAdminLogin(t, ctx, web, httpOwnerEmail)
	policyPath := "/api/v1/admin/auth/settings/mfa/email"
	response := web.call(t, ctx, "GET", policyPath, "", owner, nil)
	require.Equal(t, 200, response.status, string(response.body))
	var policy settingshttp.EmailMFASettingsResponse
	require.NoError(t, json.Unmarshal(response.body, &policy))
	response = web.call(t, ctx, "POST", policyPath, web.origin, owner, map[string]any{"expectedVersion": policy.Version, "allowed": true})
	require.Equal(t, 200, response.status, string(response.body))
	require.NoError(t, json.Unmarshal(response.body, &policy))
	foreign := f.webs[1].call(t, ctx, "POST", policyPath, f.webs[1].origin, owner, map[string]any{"expectedVersion": policy.Version, "allowed": true})
	require.Equal(t, 401, foreign.status)
	var foreignAllowed bool
	require.NoError(t, f.projects.databases[1].QueryRow(ctx, `SELECT email_factor_allowed FROM auth.mfa_settings`).Scan(&foreignAllowed))
	require.False(t, foreignAllowed)
	user := isolationAdminLogin(t, ctx, web, httpIsolationEmail)
	prepare := "/api/v1/auth/mfa/email/preparation"
	response = web.call(t, ctx, "POST", prepare, "", user, map[string]string{"email": httpIsolationEmail})
	require.Equal(t, 403, response.status)
	response = web.call(t, ctx, "POST", prepare, web.origin, user, map[string]string{"email": httpIsolationEmail})
	require.Equal(t, 202, response.status, string(response.body))
	var preparation mfamanagementhttp.EmailPreparationResponse
	require.NoError(t, json.Unmarshal(response.body, &preparation))
	code := f.code(t, "mfa-email-prepare:", preparation.Binding)
	response = web.call(t, ctx, "POST", prepare+"/confirm", web.origin, user, mfamanagementhttp.EmailPreparationConfirmation{Binding: preparation.Binding, Code: code})
	require.Equal(t, 200, response.status, string(response.body))
	user = response.cookie(t, "__Host-session")
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/email", web.origin, user, nil)
	require.Equal(t, 200, response.status, string(response.body))
	response = web.call(t, ctx, "GET", "/api/v1/auth/mfa/email", "", user, nil)
	require.Equal(t, 401, response.status, "enabling must revoke the source session")
	response = web.call(t, ctx, "POST", policyPath, web.origin, owner, map[string]any{"expectedVersion": policy.Version, "allowed": false})
	require.Equal(t, 409, response.status, "cannot silently disable an in-use factor")
	loginPath := "/api/v1/auth/mfa/email/login"
	credentials := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	response = web.call(t, ctx, "POST", loginPath, web.origin, "", credentials)
	require.Equal(t, 202, response.status, string(response.body))
	require.NotContains(t, string(response.body), `"token":`)
	var challenge mfaloginhttp.ChallengeResponse
	require.NoError(t, json.Unmarshal(response.body, &challenge))
	name := mfaloginhttp.EmailLoginCookie + "-" + string(f.projects.projects[0].Binding.ProjectID)
	cookie := response.cookie(t, name)
	binding := strings.TrimPrefix(cookie, name+"=")
	f.trackCompletion(challenge.Challenge, binding)
	code = f.code(t, "mfa-email-login:", challenge.Challenge)
	completion := mfaloginhttp.CompleteEmailLoginRequest{Challenge: challenge.Challenge, Code: code}
	foreign = f.webs[1].call(t, ctx, "POST", loginPath+"/complete", f.webs[1].origin, cookie, completion)
	require.Equal(t, 400, foreign.status)
	response = web.call(t, ctx, "POST", "/api/v1/auth/mfa/login/complete", web.origin, mfaloginhttp.LoginCookie+"="+binding, mfaloginhttp.CompleteLoginRequest{Challenge: challenge.Challenge, Code: code})
	require.Equal(t, 400, response.status, "email challenge must not be accepted by the TOTP endpoint")
	response = completeEmailMFAAfterRedisFailure(t, f, loginPath+"/complete", cookie, challenge.Challenge, binding, completion)
	require.Equal(t, 200, response.status, string(response.body))
	user = response.cookie(t, "__Host-session")
	var weak bool
	require.NoError(t, f.projects.databases[0].QueryRow(ctx, `SELECT mfa_method='email' AND strong_mfa_verified_at IS NULL FROM auth.role_bound_sessions WHERE token_hash=$1`, tokengenerate.New().Hash(strings.TrimPrefix(user, "__Host-session="))).Scan(&weak))
	require.True(t, weak, "email login must not become strong administrative proof")
	response = web.call(t, ctx, "POST", loginPath+"/complete", web.origin, cookie, completion)
	require.Equal(t, 400, response.status)
	response = web.call(t, ctx, "POST", loginPath, web.origin, "", credentials)
	require.Equal(t, 429, response.status, "email resend cooldown must survive completion")
	checkEmailMFARoleTransitions(t, f, owner)
	checkNativeEmailMFA(t, f)
	checkEmailMFAChallengeRoleChange(t, f, owner)
	cfg := runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.projects.password, EmailMFA: &f.config, Tokens: &f.tokens.configs[0], Timeout: 10 * time.Second}
	_, err := profileapp.BuildProjectProfile(ctx, f.projects.projects[0], web.origin, cfg, f.projects.deps)
	require.NoError(t, err, "cold profile must accept a fully assembled stored email factor")
	cfg.EmailMFA = nil
	_, err = profileapp.BuildProjectProfile(ctx, f.projects.projects[0], web.origin, cfg, f.projects.deps)
	require.Error(t, err, "stored factors must fail closed without the email runtime")
}

func checkNativeEmailMFA(t *testing.T, f emailMFAHTTPFixture) {
	t.Helper()
	ctx := t.Context()
	web := f.webs[0]
	// Advance only the fixture resend cooldown, never the production limit or clock.
	require.NoError(t, f.projects.deps.Redis.Del(ctx, f.prefix[0]+f.mfa[0].Digest("mfa-email-login:resend:"+httpIsolationUser)).Err())
	path := "/api/v1/auth/native/mfa/email/login"
	input := map[string]any{"email": httpIsolationEmail, "password": httpIsolationPassword, "audience": "reports", "scope": []string{"reports.read"}}
	blocked := web.call(t, ctx, "POST", path, web.origin, "", input)
	require.Equal(t, 403, blocked.status, "native transport rejects browser Origin")
	require.Contains(t, string(blocked.body), "native_transport_required")
	response := web.call(t, ctx, "POST", path, "", "", input)
	require.Equal(t, 202, response.status, string(response.body))
	require.Empty(t, response.cookies)
	var challenge tokennativehttp.NativeChallengeResponse
	require.NoError(t, json.Unmarshal(response.body, &challenge))
	f.trackCompletion(challenge.Challenge, challenge.Binding)
	code := f.code(t, "mfa-email-login:", challenge.Challenge)
	completion := tokennativehttp.NativeMFARequest{Challenge: challenge.Challenge, Binding: challenge.Binding, Code: code}
	path = "/api/v1/auth/native/mfa/email/complete"
	foreign := f.webs[1].call(t, ctx, "POST", path, "", "", completion)
	require.Equal(t, 400, foreign.status)
	wrong := web.call(t, ctx, "POST", "/api/v1/auth/native/mfa/complete", "", "", completion)
	require.Equal(t, 400, wrong.status)
	response = completeEmailMFAAfterRedisFailure(t, f, path, "", challenge.Challenge, challenge.Binding, completion)
	require.Equal(t, 200, response.status, string(response.body))
	require.Empty(t, response.cookies)
	var tokens tokennativehttp.NativeResponse
	require.NoError(t, json.Unmarshal(response.body, &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)
	parts := strings.Split(tokens.AccessToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		AMR []string `json:"amr"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Contains(t, claims.AMR, "email_otp")
	require.NotContains(t, claims.AMR, "otp")
	require.NotContains(t, claims.AMR, "recovery")
	replay := web.call(t, ctx, "POST", path, "", "", completion)
	require.Equal(t, 400, replay.status)
}

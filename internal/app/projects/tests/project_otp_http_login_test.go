package projects_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkOTPHTTPLogin(t *testing.T, f *emailIsolationFixture, webs [2]isolationHTTP, ciphers [2]*secretbox.Cipher) {
	t.Helper()
	ctx := t.Context()
	const base = "/api/v1/auth/email-otp"
	var bindings, codes, sessions [2]string
	for i, web := range webs {
		input := map[string]string{"email": httpIsolationEmail}
		response := web.call(t, ctx, "POST", base+"/request", "", "", input)
		require.Equal(t, 403, response.status)
		response = web.call(t, ctx, "POST", base+"/request", web.origin, "", input)
		require.Equal(t, 202, response.status, "%s", response.body)
		bindings[i] = response.cookie(t, "__Host-email-otp")
		for _, cookie := range response.cookies {
			require.NotEqual(t, "__Host-session", cookie.Name)
		}
		codes[i] = otpHTTPCode(t, ctx, f, ciphers[i], i, bindings[i], "", httpIsolationEmail)
	}
	for i, web := range webs {
		input := map[string]string{"code": codes[i]}
		isolationCommand(t, ctx, web, "GET", base+"/confirm", bindings[i], nil, 405, nil)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", "", input, 400, nil)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", bindings[1-i], map[string]string{"code": codes[1-i]}, 400, nil)
		wrong := string('0'+(codes[i][0]-'0'+1)%10) + codes[i][1:]
		isolationCommand(t, ctx, web, "POST", base+"/confirm", bindings[i], map[string]string{"code": wrong}, 400, nil)
		response := web.call(t, ctx, "POST", base+"/confirm", webs[1-i].origin, bindings[i], input)
		require.Equal(t, 403, response.status)
		response = web.call(t, ctx, "POST", base+"/confirm", web.origin, bindings[i], input)
		require.Equal(t, 200, response.status, "%s", response.body)
		sessions[i] = response.cookie(t, "__Host-session")
		isolationCommand(t, ctx, web, "POST", base+"/confirm", bindings[i], input, 400, nil)
		var method string
		var password, mfa bool
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT primary_method,password_verified_at IS NOT NULL,mfa_verified_at IS NOT NULL FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(sessions[i][len("__Host-session="):])).Scan(&method, &password, &mfa))
		require.Equal(t, "emailotp", method)
		require.False(t, password)
		require.False(t, mfa)
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", sessions[i], nil, 200, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", sessions[1-i], nil, 401, nil)
	}
}

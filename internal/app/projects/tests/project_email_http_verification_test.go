package projects_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	passwordrecoveryhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/recovery/transport/http"
)

func checkEmailHTTPVerificationReset(t *testing.T, ctx context.Context, f *emailIsolationFixture, webs [2]isolationHTTP) {
	t.Helper()
	var cookies, verify, reset [2]string
	address := map[string]string{"email": httpIsolationEmail}
	for i, web := range webs {
		cookies[i] = emailHTTPLogin(t, ctx, web, httpIsolationEmail, httpIsolationPassword)
		response := web.call(t, ctx, "POST", "/api/v1/auth/email/resend", "", "", address)
		require.Equal(t, 403, response.status)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/email/resend", "", address, 202, nil)
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_verification_outbox o JOIN auth.email_verifications v USING(digest) WHERE v.email_id IN(SELECT id FROM auth.user_emails WHERE user_id=$1)`, httpIsolationUser)
		verify[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Verification.URL, httpIsolationEmail)
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/email/verify?token="+verify[i], "", nil, 405, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/email/verify", "", map[string]string{"token": verify[1-i]}, 400, nil)
		response := web.call(t, ctx, "POST", "/api/v1/auth/email/verify", "https://foreign.example.test", "", map[string]string{"token": verify[i]})
		require.Equal(t, 403, response.status)
	}
	for i, web := range webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/email/verify", web.origin, "", map[string]string{"token": verify[i]})
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/email/verify", "", map[string]string{"token": verify[i]}, 400, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookies[i], nil, 200, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/forgot-password", "", address, 202, nil)
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.password_reset_outbox o JOIN auth.password_resets r USING(digest) WHERE r.user_id=$1`, httpIsolationUser)
		reset[i] = isolationEmailToken(t, f.ciphers[i][1], payload, f.configs[i].Password.ResetURL, httpIsolationEmail)
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/reset-password?token="+reset[i], "", nil, 405, nil)
		input := passwordrecoveryhttp.ResetRequest{Token: reset[1-i], NewPassword: isolationResetPassword, ConfirmPassword: isolationResetPassword}
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/reset-password", "", input, 400, nil)
		input.Token = reset[i]
		response := web.call(t, ctx, "POST", "/api/v1/auth/reset-password", "", "", input)
		require.Equal(t, 403, response.status)
	}
	for i, web := range webs {
		input := passwordrecoveryhttp.ResetRequest{Token: reset[i], NewPassword: isolationResetPassword, ConfirmPassword: isolationResetPassword}
		response := web.call(t, ctx, "POST", "/api/v1/auth/reset-password", web.origin, "", input)
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/reset-password", "", input, 400, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookies[i], nil, 401, nil)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/login/email", "", map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}, 400, nil)
		cookie := emailHTTPLogin(t, ctx, web, httpIsolationEmail, isolationResetPassword)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookie, nil, 200, nil)
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/me", cookies[1], nil, 200, nil)
		}
	}
}

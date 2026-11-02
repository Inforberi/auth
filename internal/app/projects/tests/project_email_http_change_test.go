package projects_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

func checkEmailHTTPChange(t *testing.T, ctx context.Context, f *emailIsolationFixture, webs [2]isolationHTTP) {
	t.Helper()
	const base = "/api/v1/auth/email/change"
	const newEmail = "isolation-new@example.test"
	var cookies, confirm, report [2]string
	request := accounthttp.EmailChangeRequest{Email: newEmail, Password: isolationResetPassword}
	for i, web := range webs {
		cookie := emailHTTPLogin(t, ctx, web, httpIsolationEmail, isolationResetPassword)
		response := web.call(t, ctx, "POST", "/api/v1/auth/reauthenticate/password", web.origin, cookie, map[string]string{"password": isolationResetPassword})
		require.Equal(t, 200, response.status, "%s", response.body)
		cookies[i] = response.cookie(t, "__Host-session")
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", base, cookies[1-i], request, 401, nil)
		response := web.call(t, ctx, "POST", base, "https://foreign.example.test", cookies[i], request)
		require.Equal(t, 403, response.status)
		isolationCommand(t, ctx, web, "POST", base, cookies[i], request, 202, nil)
		for _, kind := range []string{"confirm", "notice"} {
			payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='`+kind+`'`, httpIsolationUser)
			if kind == "confirm" {
				confirm[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Change.ConfirmURL, newEmail)
			} else {
				report[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Change.ReportURL, httpIsolationEmail)
			}
		}
	}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", base+"/confirm?token="+confirm[i], "", nil, 405, nil)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", "", map[string]string{"token": confirm[1-i]}, 400, nil)
		isolationCommand(t, ctx, web, "POST", base+"/report", "", map[string]string{"token": report[1-i]}, 400, nil)
	}
	for i, web := range webs {
		response := web.call(t, ctx, "POST", base+"/confirm", web.origin, "", map[string]string{"token": confirm[i]})
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", "", map[string]string{"token": confirm[i]}, 400, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookies[i], nil, 401, nil)
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/me", cookies[1], nil, 200, nil)
		}
	}
	for i, web := range webs {
		cookies[i] = emailHTTPLogin(t, ctx, web, newEmail, isolationResetPassword)
	}
	for i, web := range webs {
		response := web.call(t, ctx, "POST", base+"/report", web.origin, "", map[string]string{"token": report[i]})
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookies[i], nil, 401, nil)
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.email_change_outbox o JOIN auth.email_changes c ON c.id=o.change_id WHERE c.user_id=$1 AND o.kind='recovery'`, httpIsolationUser)
		recovery := isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Change.RecoveryURL, httpIsolationEmail)
		input := map[string]string{"token": recovery, "newPassword": httpIsolationPassword, "confirmPassword": httpIsolationPassword}
		isolationCommand(t, ctx, webs[1-i], "POST", base+"/recover", "", input, 400, nil)
		response = web.call(t, ctx, "POST", base+"/recover", web.origin, "", input)
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		isolationCommand(t, ctx, web, "POST", base+"/recover", "", input, 400, nil)
		cookie := emailHTTPLogin(t, ctx, web, httpIsolationEmail, httpIsolationPassword)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookie, nil, 200, nil)
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/me", cookies[1], nil, 200, nil)
		}
	}
}

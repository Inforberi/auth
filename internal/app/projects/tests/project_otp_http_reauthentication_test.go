package projects_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkOTPHTTPReauthentication(t *testing.T, f *emailIsolationFixture, webs [2]isolationHTTP, ciphers [2]*secretbox.Cipher) {
	t.Helper()
	ctx := t.Context()
	const base = "/api/v1/auth/reauthenticate/email"
	const address = "otp-reauth@example.test"
	var sessions, others, bindings, codes [2]string
	for i, db := range f.projects.databases {
		_, err := db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, emailHTTPBindingUser)
		require.NoError(t, err)
		f.users[i] = append(f.users[i], emailHTTPBindingUser)
		_, err = db.Exec(ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://accounts.google.com','otp-http-reauth')`, emailHTTPBindingUser)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp())`, emailHTTPBindingUser, address)
		require.NoError(t, err)
		sessions[i] = seedEmailHTTPOIDCSession(t, ctx, f, i)
		others[i] = seedEmailHTTPOIDCSession(t, ctx, f, i)
	}
	for i, web := range webs {
		input := map[string]string{"email": address}
		isolationCommand(t, ctx, web, "POST", base+"/request", sessions[1-i], input, 401, nil)
		response := web.call(t, ctx, "POST", base+"/request", web.origin, sessions[i], input)
		require.Equal(t, 202, response.status, "%s", response.body)
		bindings[i] = response.cookie(t, "__Host-email-reauthentication")
		codes[i] = otpHTTPCode(t, ctx, f, ciphers[i], i, bindings[i], "reauth:", address)
	}
	for i, web := range webs {
		input := map[string]string{"code": codes[i]}
		isolationCommand(t, ctx, web, "POST", base+"/confirm", others[i]+"; "+bindings[i], input, 400, nil)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", sessions[i]+"; "+bindings[1-i], map[string]string{"code": codes[1-i]}, 400, nil)
		response := web.call(t, ctx, "POST", base+"/confirm", web.origin, sessions[i]+"; "+bindings[i], input)
		require.Equal(t, 200, response.status, "%s", response.body)
		rotated := response.cookie(t, "__Host-session")
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", sessions[i], nil, 401, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", others[i], nil, 200, nil)
		isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", rotated, nil, 200, nil)
		isolationCommand(t, ctx, web, "POST", base+"/confirm", rotated+"; "+bindings[i], input, 400, nil)
		var emailProof, password, mfa bool
		var method string
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT primary_method,email_reauthenticated_at IS NOT NULL,password_verified_at IS NOT NULL,mfa_verified_at IS NOT NULL FROM auth.sessions WHERE token_hash=$1`, tokengenerate.New().Hash(rotated[len("__Host-session="):])).Scan(&method, &emailProof, &password, &mfa))
		require.Equal(t, "oidc", method)
		require.True(t, emailProof)
		require.False(t, password)
		require.False(t, mfa)
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/me", sessions[1], nil, 200, nil)
		}
	}
}

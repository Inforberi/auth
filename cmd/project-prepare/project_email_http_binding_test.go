package main

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkEmailHTTPBinding(t *testing.T, ctx context.Context, f *emailIsolationFixture, webs [2]isolationHTTP, owners [2]string) {
	t.Helper()
	var cookies [2]string
	for i, db := range f.projects.databases {
		_, err := db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, emailHTTPBindingUser)
		require.NoError(t, err)
		f.users[i] = append(f.users[i], emailHTTPBindingUser)
		_, err = db.Exec(ctx, `INSERT INTO auth.linked_identities(user_id,issuer,subject) VALUES($1,'https://accounts.google.com','email-http-binding')`, emailHTTPBindingUser)
		require.NoError(t, err)
		cookies[i] = seedEmailHTTPOIDCSession(t, ctx, f, i)
	}
	const requestPath = "/api/v1/admin/users/" + emailHTTPBindingUser + "/email-binding"
	const confirmPath = "/api/v1/auth/email/binding/confirm"
	for i, web := range webs {
		request := map[string]string{"email": "http-bind@example.test"}
		isolationCommand(t, ctx, web, "POST", requestPath, owners[1-i], request, 401, nil)
		isolationCommand(t, ctx, web, "POST", requestPath, owners[i], request, 202, nil)
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT payload FROM auth.email_bindings WHERE user_id=$1`, emailHTTPBindingUser)
		plain, err := f.ciphers[i][0].Open(payload)
		require.NoError(t, err)
		var message struct{ To, Body string }
		require.NoError(t, json.Unmarshal(plain, &message))
		clear(plain)
		require.Equal(t, "http-bind@example.test", message.To)
		code := regexp.MustCompile(`\b[0-9]{8}\b`).FindString(message.Body)
		require.Len(t, code, 8)
		input := accounthttp.ConfirmEmailBindingRequest{Code: code}
		isolationCommand(t, ctx, web, "POST", confirmPath, "", input, 401, nil)
		isolationCommand(t, ctx, web, "POST", confirmPath, cookies[1-i], input, 401, nil)
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "POST", confirmPath, cookies[1], input, 400, nil)
		}
		other := seedEmailHTTPOIDCSession(t, ctx, f, i)
		isolationCommand(t, ctx, web, "POST", confirmPath, owners[i], input, 400, nil)
		response := web.call(t, ctx, "POST", confirmPath, web.origin, other, input)
		require.Equal(t, 200, response.status, "%s", response.body)
		requireNoEmailLoginCookie(t, response)
		for _, cookie := range []string{cookies[i], other} {
			isolationCommand(t, ctx, web, "GET", "/api/v1/auth/me", cookie, nil, 401, nil)
		}
		if i == 0 {
			isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/me", cookies[1], nil, 200, nil)
		}
		var verified bool
		require.NoError(t, f.projects.databases[i].QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM auth.user_emails WHERE user_id=$1 AND email='http-bind@example.test'`, emailHTTPBindingUser).Scan(&verified))
		require.True(t, verified)
	}
}

// The target's existing OIDC session is a fixture precondition; provider login is tested separately.
func seedEmailHTTPOIDCSession(t *testing.T, ctx context.Context, f *emailIsolationFixture, project int) string {
	t.Helper()
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.projects.databases[project].Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','oidc',clock_timestamp(),'email HTTP binding fixture','127.0.0.1' FROM auth.users WHERE id=$2`, tokens.Hash(raw), emailHTTPBindingUser)
	require.NoError(t, err)
	return "__Host-session=" + raw
}

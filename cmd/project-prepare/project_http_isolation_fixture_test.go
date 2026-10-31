package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

const (
	httpIsolationUser     = "f8800000-0000-4000-8000-000000000088"
	httpIsolationEmail    = "http-isolation@example.test"
	httpIsolationPassword = "HTTP-isolation-password-72!"
)

type isolationHTTP struct {
	server *httptest.Server
	origin string
	trace  func(string, string, any)
}

type isolationHTTPResponse struct {
	status  int
	cookies []*http.Cookie
	body    []byte
}

func (w isolationHTTP) call(t *testing.T, ctx context.Context, method, path, origin, cookie string, input any, headers ...http.Header) isolationHTTPResponse {
	t.Helper()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		require.NoError(t, err)
	}
	if w.trace != nil {
		w.trace(path, cookie, input)
	}
	req, err := http.NewRequestWithContext(ctx, method, w.server.URL+path, strings.NewReader(string(body)))
	require.NoError(t, err)
	parsed, err := url.Parse(w.origin)
	require.NoError(t, err)
	req.Host = parsed.Host
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for _, extra := range headers {
		for name, values := range extra {
			req.Header[name] = values
		}
	}
	response, err := w.server.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	require.NoError(t, err)
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
	return isolationHTTPResponse{status: response.StatusCode, cookies: response.Cookies(), body: data}
}

func (r isolationHTTPResponse) cookie(t *testing.T, name string) string {
	t.Helper()
	for _, cookie := range r.cookies {
		if cookie.Name == name && cookie.Value != "" && cookie.MaxAge >= 0 {
			require.True(t, cookie.Secure && cookie.HttpOnly)
			require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			require.Empty(t, cookie.Domain)
			require.Equal(t, "/", cookie.Path)
			return cookie.Name + "=" + cookie.Value
		}
	}
	t.Fatalf("missing live %s cookie", name)
	return ""
}

func seedHTTPIsolationUser(t *testing.T, ctx context.Context, db *pgx.Conn, hash string) {
	t.Helper()
	var occupied bool
	require.NoError(t, db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.users WHERE id=$1) OR EXISTS(SELECT 1 FROM auth.roles WHERE key='http_isolation_mfa')`, httpIsolationUser).Scan(&occupied))
	require.False(t, occupied)
	_, err := db.Exec(ctx, `CREATE TEMP TABLE http_isolation_policy_before AS TABLE auth.auth_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, query := range []string{
			`DELETE FROM auth.mfa_audit WHERE user_id=$1`,
			`DELETE FROM auth.password_audit WHERE user_id=$1 OR actor_id=$1`,
			`DELETE FROM auth.sessions WHERE user_id=$1`,
			`DELETE FROM auth.users WHERE id=$1`,
		} {
			_, err := db.Exec(cleanup, query, httpIsolationUser)
			require.NoError(t, err)
		}
		_, err := db.Exec(cleanup, `DELETE FROM auth.roles WHERE key='http_isolation_mfa';
 DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM http_isolation_policy_before`)
		require.NoError(t, err)
	})
	_, err = db.Exec(ctx, `UPDATE auth.auth_settings SET version=version+1,password_enabled=true,password_email_verification='disabled',
 email_otp_enabled=false,google_enabled=false,telegram_enabled=false,registration_enabled=false,google_registration_enabled=false,
 telegram_registration_enabled=false,token_session_exchange_enabled=false,token_native_enabled=false`)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, httpIsolationUser)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp())`, httpIsolationUser, httpIsolationEmail)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) SELECT $1,id,$2 FROM auth.user_emails WHERE user_id=$1`, httpIsolationUser, hash)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `WITH r AS(INSERT INTO auth.roles(key,name) VALUES('http_isolation_mfa','HTTP isolation') RETURNING id)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM r`, httpIsolationUser)
	require.NoError(t, err)
}

func httpIsolationTrace(prefix string, cipher *secretbox.Cipher, keys map[string]struct{}) func(string, string, any) {
	return func(path, rawCookie string, input any) {
		var challenge string
		switch v := input.(type) {
		case mfahttp.LoginEnrollmentRequest:
			challenge = v.Challenge
		case mfahttp.ConfirmLoginEnrollmentRequest:
			challenge = v.Challenge
		case mfahttp.CompleteLoginRequest:
			challenge = v.Challenge
		default:
			return
		}
		r := &http.Request{Header: http.Header{"Cookie": []string{rawCookie}}}
		binding := ""
		if cookie, err := r.Cookie(mfahttp.LoginCookie); err == nil {
			binding = cookie.Value
		}
		purpose := "enrollment"
		if strings.HasSuffix(path, "/complete") {
			purpose = "complete"
		}
		keys[prefix+"login:"+purpose+":subject:"+cipher.Digest(challenge+":"+binding)] = struct{}{}
	}
}

package projects_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
)

func (f projectProfileFixture) httpSessions(t *testing.T, ctx context.Context, origin string, server *httptest.Server, current string) string {
	t.Helper()
	host, err := url.Parse(origin)
	require.NoError(t, err)
	request := func(method, path, requestOrigin, cookie, body string) (int, []byte, []*http.Cookie) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, server.URL+path, strings.NewReader(body))
		require.NoError(t, err)
		r.Host = host.Host
		r.Header.Set("Content-Type", "application/json")
		if requestOrigin != "" {
			r.Header.Set("Origin", requestOrigin)
		}
		if cookie != "" {
			r.Header.Set("Cookie", cookie)
		}
		response, err := server.Client().Do(r)
		require.NoError(t, err)
		payload, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Empty(t, response.Header.Get("Access-Control-Allow-Origin"))
		return response.StatusCode, payload, response.Cookies()
	}
	sessionCookie := func(cookies []*http.Cookie) string {
		t.Helper()
		for _, cookie := range cookies {
			if cookie.Name == "__Host-session" {
				require.True(t, cookie.HttpOnly && cookie.Secure)
				require.Empty(t, cookie.Domain)
				require.Equal(t, "/", cookie.Path)
				return cookie.Name + "=" + cookie.Value
			}
		}
		t.Fatal("missing session cookie")
		return ""
	}
	login := func() string {
		t.Helper()
		code, _, cookies := request("POST", "/api/v1/auth/login/email", origin, "", `{"email":"runtime-email@example.test","password":"`+f.password+`"}`)
		require.Equal(t, 200, code)
		return sessionCookie(cookies)
	}
	code, _, _ := request("GET", "/api/v1/auth/me", "", "", "")
	require.Equal(t, 401, code)
	code, body, _ := request("GET", "/api/v1/auth/me", "", current, "")
	require.Equal(t, 200, code)
	var me sessionhttp.MeResponse
	require.NoError(t, json.Unmarshal(body, &me))
	require.Equal(t, f.sourceUser, me.UserID)
	require.NotEmpty(t, me.SessionID)
	second := login()
	code, body, _ = request("GET", "/api/v1/auth/me", "", second, "")
	require.Equal(t, 200, code)
	var other sessionhttp.MeResponse
	require.NoError(t, json.Unmarshal(body, &other))
	code, body, _ = request("GET", "/api/v1/auth/sessions", "", current, "")
	require.Equal(t, 200, code)
	var page sessionhttp.SessionsResponse
	require.NoError(t, json.Unmarshal(body, &page))
	secondID := other.SessionID
	listedCurrent, listedSecond := false, false
	for _, session := range page.Sessions {
		switch session.ID {
		case me.SessionID:
			require.True(t, session.Current)
			listedCurrent = true
		case secondID:
			require.False(t, session.Current)
			listedSecond = true
		}
	}
	require.True(t, listedCurrent && listedSecond)
	code, _, _ = request("GET", "/api/v1/auth/sessions?before=invalid", "", current, "")
	require.Equal(t, 400, code)
	code, _, _ = request("DELETE", "/api/v1/auth/sessions/"+secondID, "", current, "")
	require.Equal(t, 403, code)
	code, _, _ = request("DELETE", "/api/v1/auth/sessions/"+secondID, origin, current, "")
	require.Equal(t, 204, code)
	code, _, _ = request("GET", "/api/v1/auth/me", "", second, "")
	require.Equal(t, 401, code)
	code, _, _ = request("DELETE", "/api/v1/auth/sessions/"+secondID, origin, current, "")
	require.Equal(t, 404, code)
	code, _, cookies := request("POST", "/api/v1/auth/session/activity", origin, current, "")
	require.Equal(t, 200, code)
	require.Empty(t, cookies, "ordinary session activity must not extend its cookie")
	code, _, cookies = request("POST", "/api/v1/auth/session/rotate", "https://foreign.example.test", current, "")
	require.Equal(t, 403, code)
	require.Empty(t, cookies)
	code, _, cookies = request("POST", "/api/v1/auth/session/rotate", origin, current, "")
	require.Equal(t, 204, code)
	rotated := sessionCookie(cookies)
	require.NotEqual(t, current, rotated)
	code, _, _ = request("GET", "/api/v1/auth/me", "", current, "")
	require.Equal(t, 401, code)
	code, body, _ = request("GET", "/api/v1/auth/me", "", rotated, "")
	require.Equal(t, 200, code)
	var after sessionhttp.MeResponse
	require.NoError(t, json.Unmarshal(body, &after))
	require.Equal(t, me, after, "rotation replaces only the verifier")
	code, _, cookies = request("POST", "/api/v1/auth/logout", origin, rotated, "")
	require.Equal(t, 204, code)
	require.Equal(t, "__Host-session=", sessionCookie(cookies))
	code, _, cookies = request("POST", "/api/v1/auth/logout", origin, rotated, "")
	require.Equal(t, 401, code)
	require.Equal(t, "__Host-session=", sessionCookie(cookies))
	current, second = login(), login()
	code, _, cookies = request("POST", "/api/v1/auth/logout-all", origin, current, "")
	require.Equal(t, 204, code)
	require.Equal(t, "__Host-session=", sessionCookie(cookies))
	for _, cookie := range []string{current, second} {
		code, _, _ = request("GET", "/api/v1/auth/me", "", cookie, "")
		require.Equal(t, 401, code)
	}
	return login()
}

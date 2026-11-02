package projects_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	tokenhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
)

func checkProjectNativeIsolation(t *testing.T, ctx context.Context, f tokenIsolationFixture, browser tokenIsolationBrowser) {
	t.Helper()
	var native [2]tokenhttp.NativeResponse
	login := tokenhttp.NativePasswordRequest{Email: httpIsolationEmail, Password: httpIsolationPassword, Audience: "reports", Scope: []accessdomain.PermissionKey{"reports.read"}}
	// Native transport intentionally has no Origin, Cookie or Authorization header.
	for i, web := range f.webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/native/password/login", "", "", login)
		require.Equal(t, 200, response.status, "%s", response.body)
		require.Empty(t, response.cookies)
		require.NoError(t, json.Unmarshal(response.body, &native[i]))
		claims, err := browser.verifiers[i].VerifySignature(ctx, native[i].AccessToken, time.Now())
		require.NoError(t, err)
		require.Equal(t, httpIsolationUser, claims.Subject)
		require.True(t, f.inspect(t, ctx, i, native[i].AccessToken, i, 200).Active)
	}
	for i, web := range f.webs {
		foreign := tokenhttp.RefreshRequest{RefreshToken: native[1-i].RefreshToken}
		for _, path := range []string{"/api/v1/auth/token/refresh", "/api/v1/auth/token/logout"} {
			response := web.call(t, ctx, "POST", path, "", "", foreign)
			expected := 401
			if path == "/api/v1/auth/token/logout" {
				expected = 204
			}
			require.Equal(t, expected, response.status, "%s", response.body)
			require.Empty(t, response.cookies)
		}
		response := web.call(t, ctx, "POST", "/api/v1/auth/token/refresh", web.origin, "", tokenhttp.RefreshRequest{RefreshToken: native[i].RefreshToken})
		require.Equal(t, 403, response.status)
		require.True(t, f.inspect(t, ctx, i, native[i].AccessToken, i, 200).Active)
	}
	refresh := func(i int, raw string, status int) tokenhttp.NativeResponse {
		t.Helper()
		response := f.webs[i].call(t, ctx, "POST", "/api/v1/auth/token/refresh", "", "", tokenhttp.RefreshRequest{RefreshToken: raw})
		require.Equal(t, status, response.status, "%s", response.body)
		require.Empty(t, response.cookies)
		var result tokenhttp.NativeResponse
		if status == 200 {
			require.NoError(t, json.Unmarshal(response.body, &result))
		}
		return result
	}
	a := refresh(0, native[0].RefreshToken, 200)
	require.NotEqual(t, native[0].RefreshToken, a.RefreshToken)
	refresh(0, native[0].RefreshToken, 401)
	require.False(t, f.inspect(t, ctx, 0, a.AccessToken, 0, 200).Active, "replay must revoke only A's family")
	require.True(t, f.inspect(t, ctx, 1, native[1].AccessToken, 1, 200).Active)
	b := refresh(1, native[1].RefreshToken, 200)
	require.True(t, f.inspect(t, ctx, 1, b.AccessToken, 1, 200).Active)
	response := f.webs[0].call(t, ctx, "POST", "/api/v1/auth/native/password/login", "", "", login)
	require.Equal(t, 200, response.status, "%s", response.body)
	var another tokenhttp.NativeResponse
	require.NoError(t, json.Unmarshal(response.body, &another))
	response = f.webs[0].call(t, ctx, "POST", "/api/v1/auth/token/logout", "", "", tokenhttp.RefreshRequest{RefreshToken: another.RefreshToken})
	require.Equal(t, 204, response.status, "%s", response.body)
	require.False(t, f.inspect(t, ctx, 0, another.AccessToken, 0, 200).Active)
	require.True(t, f.inspect(t, ctx, 1, b.AccessToken, 1, 200).Active)
	isolationCommand(t, ctx, f.webs[0], "POST", "/api/v1/auth/logout-all", browser.cookies[0], nil, 204, nil)
	require.False(t, f.inspect(t, ctx, 0, browser.tokens[0], 0, 200).Active)
	require.True(t, f.inspect(t, ctx, 1, browser.tokens[1], 1, 200).Active)
	require.True(t, f.inspect(t, ctx, 1, b.AccessToken, 1, 200).Active)
	isolationCommand(t, ctx, f.webs[0], "GET", "/api/v1/auth/me", browser.cookies[0], nil, 401, nil)
	isolationCommand(t, ctx, f.webs[1], "GET", "/api/v1/auth/me", browser.cookies[1], nil, 200, nil)
	// Revocation changes online authority, not the cryptographic validity before JWT expiry.
	_, err := browser.verifiers[0].VerifySignature(ctx, browser.tokens[0], time.Now())
	require.NoError(t, err)
}

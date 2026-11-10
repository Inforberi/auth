package projects_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	tokenintrospectionhttp "github.com/Inforberi/financial-intelligence/internal/auth/token/introspection/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/transport/http"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type tokenIsolationBrowser struct {
	cookies   [2]string
	tokens    [2]string
	verifiers [2]*authjwt.Verifier
}

func checkProjectTokenIsolation(t *testing.T, ctx context.Context, f tokenIsolationFixture) tokenIsolationBrowser {
	t.Helper()
	var browser tokenIsolationBrowser
	var public [2][]byte
	var etags [2]string
	var kids [2]string
	for i, web := range f.webs {
		public[i], etags[i] = readIsolationJWKS(t, ctx, web, "", 200)
		var jwks struct {
			Keys []struct {
				ID string `json:"kid"`
			} `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(public[i], &jwks))
		require.Len(t, jwks.Keys, 1)
		kids[i] = jwks.Keys[0].ID
		keys, err := authjwt.ParsePublicKeys(public[i])
		require.NoError(t, err)
		browser.verifiers[i], err = authjwt.NewVerifier(authjwt.Expectations{Issuer: web.origin, Audience: "reports", Mode: authjwt.Strict}, keys, time.Now())
		require.NoError(t, err)
		browser.cookies[i] = isolationSessionLogin(t, ctx, web)
		var exchanged tokenhttp.ExchangeResponse
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/token/exchange", browser.cookies[i], map[string]any{"audience": "reports", "scope": []string{"reports.read"}}, 200, &exchanged)
		require.Equal(t, "Bearer", exchanged.TokenType)
		browser.tokens[i] = exchanged.AccessToken
		claims, err := browser.verifiers[i].VerifySignature(ctx, exchanged.AccessToken, time.Now())
		require.NoError(t, err)
		require.Equal(t, httpIsolationUser, claims.Subject)
		require.Equal(t, web.origin, claims.Issuer)
		require.Equal(t, "reports.read", claims.Scope)
		own := f.inspect(t, ctx, i, exchanged.AccessToken, i, 200)
		require.True(t, own.Active)
		require.Equal(t, httpIsolationUser, own.Subject)
	}
	require.NotEmpty(t, kids[0])
	require.Equal(t, kids[0], kids[1], "fixture must exercise the same kid across independent project keys")
	require.NotEqual(t, public[0], public[1], "projects must publish independent signing keys")
	require.NotEqual(t, etags[0], etags[1])
	for i, web := range f.webs {
		readIsolationJWKS(t, ctx, web, etags[i], 304)
		other, _ := readIsolationJWKS(t, ctx, web, etags[1-i], 200)
		require.Equal(t, public[i], other)
		_, err := browser.verifiers[i].VerifySignature(ctx, browser.tokens[1-i], time.Now())
		require.ErrorIs(t, err, authjwt.ErrInvalidToken)
		// Correct foreign key material does not make the other issuer trusted.
		keys, err := authjwt.ParsePublicKeys(public[1-i])
		require.NoError(t, err)
		wrongIssuer, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: web.origin, Audience: "reports", Mode: authjwt.Strict}, keys, time.Now())
		require.NoError(t, err)
		_, err = wrongIssuer.VerifySignature(ctx, browser.tokens[1-i], time.Now())
		require.ErrorIs(t, err, authjwt.ErrInvalidToken)
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/token/exchange", browser.cookies[1-i], map[string]any{"audience": "reports", "scope": []string{"reports.read"}}, 401, nil)
		f.inspect(t, ctx, i, browser.tokens[i], 1-i, 401)
		require.Equal(t, tokenintrospectionhttp.IntrospectionResponse{}, f.inspect(t, ctx, i, browser.tokens[1-i], i, 200))
		var exported tokenhttp.ExchangeResponse
		isolationCommand(t, ctx, web, "POST", "/api/v1/auth/token/exchange", browser.cookies[i], map[string]any{"audience": "reports-export", "scope": []string{"reports.read"}}, 200, &exported)
		f.inspect(t, ctx, i, exported.AccessToken, i, 403)
		require.True(t, f.inspect(t, ctx, i, browser.tokens[i], i, 200).Active, "negative peer/audience checks must not revoke valid credentials")
	}
	return browser
}

func (f tokenIsolationFixture) inspect(t *testing.T, ctx context.Context, project int, token string, credentials, status int) tokenintrospectionhttp.IntrospectionResponse {
	t.Helper()
	basic := base64.StdEncoding.EncodeToString([]byte(isolationTokenClient + ":" + f.secrets[credentials]))
	response := f.webs[project].call(t, ctx, "POST", "/api/v1/internal/auth/token/introspect", "", "", tokenintrospectionhttp.IntrospectionRequest{Token: token}, http.Header{"Authorization": {"Basic " + basic}})
	require.Equal(t, status, response.status, "%s", response.body)
	var result tokenintrospectionhttp.IntrospectionResponse
	if status == 200 {
		require.NoError(t, json.Unmarshal(response.body, &result))
	}
	return result
}

func readIsolationJWKS(t *testing.T, ctx context.Context, web isolationHTTP, etag string, status int) ([]byte, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, "GET", web.server.URL+"/.well-known/jwks.json", nil)
	require.NoError(t, err)
	origin, err := url.Parse(web.origin)
	require.NoError(t, err)
	request.Host = origin.Host
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := web.server.Client().Do(request)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	require.NoError(t, err)
	require.Equal(t, status, response.StatusCode, "%s", body)
	require.Equal(t, "public, max-age=30, must-revalidate", response.Header.Get("Cache-Control"))
	require.NotEmpty(t, response.Header.Get("ETag"))
	require.Empty(t, response.Cookies())
	if status == 200 {
		var public struct {
			Keys []map[string]any `json:"keys"`
		}
		require.NoError(t, json.Unmarshal(body, &public))
		require.Len(t, public.Keys, 1)
		require.NotContains(t, public.Keys[0], "d")
	}
	return body, response.Header.Get("ETag")
}

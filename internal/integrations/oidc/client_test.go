package oidcclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
)

func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any, alg string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": alg, "kid": "key1", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	content := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return content + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestProviderProof(t *testing.T) {
	for _, profile := range []struct {
		name, issuer, authorization, token, keys string
		style                                    oauth2.AuthStyle
	}{
		{"telegram", "https://oauth.telegram.org", "https://oauth.telegram.org/auth", "https://oauth.telegram.org/token", "https://oauth.telegram.org/.well-known/jwks.json", oauth2.AuthStyleInHeader},
		{"google", "https://accounts.google.com", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/oauth2/v3/certs", oauth2.AuthStyleInParams},
	} {
		t.Run(profile.name, func(t *testing.T) {
			testProviderProof(t, profile.issuer, profile.authorization, profile.token, profile.keys, profile.style)
		})
	}
}

func testProviderProof(t *testing.T, issuer, authorization, tokenURL, keys string, style oauth2.AuthStyle) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	flow := domain.Flow{Verifier: "verifier", Nonce: "browser-nonce"}
	var raw string
	status := http.StatusOK
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/keys" {
			httpxJSON := map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key1",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}}
			_ = json.NewEncoder(w).Encode(httpxJSON)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		id, secret, basic := r.BasicAuth()
		authOK := basic && id == "123" && secret == "view-secret"
		if style == oauth2.AuthStyleInParams {
			authOK = !basic && r.Form.Get("client_secret") == "view-secret"
		}
		if !authOK || r.Form.Get("client_id") != "123" || r.Form.Get("code_verifier") != flow.Verifier ||
			r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != "https://auth.example/api/v1/auth/telegram/callback" {
			t.Error("incorrect code exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": raw})
	}))
	defer server.Close()
	client := New(t.Context(), Config{Issuer: issuer, AuthorizationURL: authorization, TokenURL: tokenURL, KeysURL: keys, AuthStyle: style, ClientID: "123", ClientSecret: "fixture-secret", RedirectURI: "https://auth.example/api/v1/auth/telegram/callback"})
	defer client.Close()
	client.oauth.Endpoint.TokenURL = server.URL + "/token"
	client.http.client = server.Client()
	client.keys = oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), server.Client()), server.URL+"/keys")
	client = client.WithCredentials("123", "view-secret")
	auth, err := url.Parse(client.AuthorizationURL("state", flow))
	if err != nil || auth.Scheme+"://"+auth.Host+auth.Path != authorization || auth.Query().Get("scope") != "openid" ||
		auth.Query().Get("nonce") != flow.Nonce || auth.Query().Get("state") != "state" || auth.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("invalid authorization URL", auth, err)
	}
	for _, tc := range []struct {
		name    string
		mutate  func(map[string]any)
		invalid bool
		key     *rsa.PrivateKey
		alg     string
	}{
		{name: "valid"},
		{name: "missing nonce", invalid: true, mutate: func(c map[string]any) { delete(c, "nonce") }},
		{name: "empty subject", invalid: true, mutate: func(c map[string]any) { c["sub"] = "" }},
		{name: "legacy google issuer", invalid: issuer != "https://accounts.google.com", mutate: func(c map[string]any) { c["iss"] = "accounts.google.com" }},
		{name: "issuer", invalid: true, mutate: func(c map[string]any) { c["iss"] = "https://evil.example" }},
		{name: "audience", invalid: true, mutate: func(c map[string]any) { c["aud"] = "456" }},
		{name: "nonce", invalid: true, mutate: func(c map[string]any) { c["nonce"] = "other-browser" }},
		{name: "expiry", invalid: true, mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{name: "future issued", invalid: true, mutate: func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() }},
		{name: "multi audience", invalid: true, mutate: func(c map[string]any) { c["aud"] = []string{"123", "456"} }},
		{name: "azp", invalid: true, mutate: func(c map[string]any) { c["azp"] = "456" }},
		{name: "signature", invalid: true, key: otherKey},
		{name: "algorithm", invalid: true, alg: "HS256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": issuer, "sub": "opaque-subject", "aud": "123", "nonce": flow.Nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			signer := key
			if tc.key != nil {
				signer = tc.key
			}
			alg := tc.alg
			if alg == "" {
				alg = "RS256"
			}
			raw = signToken(t, signer, claims, alg)
			identity, err := client.Verify(t.Context(), "code", flow)
			if tc.invalid {
				if !errors.Is(err, domain.ErrInvalidFlow) {
					t.Fatal("invalid proof accepted", identity, err)
				}
			} else if err != nil || identity.Issuer != issuer || identity.Subject != "opaque-subject" {
				t.Fatal(identity, err)
			}
		})
	}
	status = http.StatusServiceUnavailable
	if _, err := client.Verify(t.Context(), "code", flow); err == nil || errors.Is(err, domain.ErrInvalidFlow) {
		t.Fatal("provider outage masked", err)
	}
}

func TestUntrustedEndpoint(t *testing.T) {
	transport, _ := newHTTPClient("https://oauth.telegram.org/token", "https://oauth.telegram.org/.well-known/jwks.json", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/oauth2/v3/certs")
	defer transport.transport.CloseIdleConnections()
	for _, endpoint := range []string{"http://oauth.telegram.org/token", "https://evil.example/token", "https://oauth.telegram.org/other", "https://oauth.telegram.org:444/token", "https://oauth2.googleapis.com/token?override=1", "https://www.googleapis.com/oauth2/v3/certs#fragment", "https://accounts.google.com/token"} {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(r)
		if response != nil {
			_ = response.Body.Close()
		}
		if err == nil {
			t.Fatal("untrusted endpoint accepted")
		}
	}
}

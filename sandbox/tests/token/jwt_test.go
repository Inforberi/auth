package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func passwordInput(user, permission string) map[string]any {
	return map[string]any{"email": user + "@sandbox.example", "password": "Sandbox-" + strings.ToUpper(user[:1]) + user[1:] + "-2026!", "audience": "sandbox-strict", "scope": []string{permission}}
}

func nativeLogin(t *testing.T, api *http.Client) testsupport.TokenResponse {
	t.Helper()
	var token testsupport.TokenResponse
	h := testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), &token, 200)
	if token.AccessToken == "" || token.RefreshToken == "" || h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid native output")
	}
	// Never print opaque tokens, even on a failed fixture.
	if _, err := base64.RawURLEncoding.DecodeString(token.RefreshToken); err != nil {
		t.Fatal("noncanonical refresh fixture")
	}
	return token
}

func TestJWTAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_ACCEPTANCE") != "1" {
		t.Skip("explicit live auth-sandbox test; run task sandbox:jwt")
	}
	api, roots := testsupport.SandboxClient(t, false)
	admin := testsupport.AdminLogin(t)
	setIssuance(t, admin, true, true)
	t.Cleanup(func() { setIssuance(t, admin, true, true) })
	strict, local := testsupport.NewConsumer(t, roots, authjwt.Strict), testsupport.NewConsumer(t, roots, authjwt.Local)
	browser := testsupport.UserLogin(t)

	t.Run("JWKS metadata and secret-free public keys", func(t *testing.T) {
		var keys struct {
			Keys []map[string]json.RawMessage `json:"keys"`
		}
		h := testsupport.Request(t, api, "GET", "/.well-known/jwks.json", nil, &keys, 200)
		if len(keys.Keys) != 1 || keys.Keys[0]["d"] != nil || h.Get("ETag") == "" {
			t.Fatal("invalid public-only JWKS")
		}
		testsupport.Request(t, api, "GET", "/.well-known/jwks.json", nil, nil, 304, "If-None-Match", h.Get("ETag"))
		testsupport.Request(t, api, "HEAD", "/.well-known/jwks.json", nil, nil, 200)
	})

	t.Run("cookie exchange strict versus local revocation", func(t *testing.T) {
		browser := testsupport.UserLogin(t)
		s := testsupport.Exchange(t, browser, "sandbox-strict")
		l := testsupport.Exchange(t, browser, "sandbox-local")
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		testsupport.Consume(t, local, l.AccessToken, "sandbox.records.read", 204)
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.write", 403)
		testsupport.Consume(t, strict, s.AccessToken+"x", "sandbox.records.read", 401)
		testsupport.Consume(t, strict, l.AccessToken, "sandbox.records.read", 401)
		testsupport.Consume(t, local, s.AccessToken, "sandbox.records.read", 401)
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 401, "Cookie", "session=ambiguous")
		testsupport.Request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Authorization", "Bearer "+s.AccessToken)
		testsupport.Request(t, browser, "POST", "/api/v1/auth/token/exchange", testsupport.Resource("sandbox-strict"), nil, 403, "Origin", "https://hostile.example")
		testsupport.Request(t, browser, "POST", "/api/v1/auth/logout", nil, nil, 204, "Origin", testsupport.SandboxURL)
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 401)
		testsupport.Consume(t, local, l.AccessToken, "sandbox.records.read", 204)
	})

	t.Run("native refresh replay and independent logout", func(t *testing.T) {
		first := nativeLogin(t, api)
		testsupport.Consume(t, strict, first.AccessToken, "sandbox.records.read", 204)
		var next testsupport.TokenResponse
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": first.RefreshToken}, &next, 200)
		if first.RefreshToken == next.RefreshToken || next.RefreshToken == "" {
			t.Fatal("refresh did not rotate")
		}
		testsupport.Consume(t, strict, next.AccessToken, "sandbox.records.read", 204)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": next.RefreshToken}, nil, 429)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": first.RefreshToken}, nil, 401)
		testsupport.Consume(t, strict, next.AccessToken, "sandbox.records.read", 401)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": next.RefreshToken}, nil, 401)
		other := nativeLogin(t, api)
		testsupport.Consume(t, strict, other.AccessToken, "sandbox.records.read", 204)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": other.RefreshToken}, nil, 204)
		testsupport.Consume(t, strict, other.AccessToken, "sandbox.records.read", 401)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": other.RefreshToken}, nil, 204)
	})

	t.Run("issuance switches do not disable introspection or logout", func(t *testing.T) {
		s := testsupport.Exchange(t, browser, "sandbox-strict")
		native := nativeLogin(t, api)
		setIssuance(t, admin, false, false)
		testsupport.Request(t, browser, "POST", "/api/v1/auth/token/exchange", testsupport.Resource("sandbox-strict"), nil, 403, "Origin", testsupport.SandboxURL)
		testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, 404)
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": native.RefreshToken}, nil, 204)
		testsupport.Consume(t, strict, native.AccessToken, "sandbox.records.read", 401)
		setIssuance(t, admin, true, true)
	})

	t.Run("native and introspection reject browser credentials", func(t *testing.T) {
		for _, header := range []string{"Origin", "Cookie", "Authorization"} {
			want := 400
			if header == "Origin" {
				want = 403
			}
			testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, want, header, "untrusted")
		}
		testsupport.Request(t, api, "OPTIONS", "/api/v1/auth/native/password/login", nil, nil, 403)
		testsupport.Request(t, api, "POST", "/api/v1/internal/auth/token/introspect", map[string]string{"token": "invalid"}, nil, 401)
	})
	t.Run("service credentials are not user credentials", func(t *testing.T) {
		s := testsupport.Exchange(t, browser, "sandbox-strict")
		bad, err := authjwt.NewConsumer(t.Context(), authjwt.ConsumerConfig{
			Expected: authjwt.Expectations{Issuer: testsupport.SandboxURL, Audience: "sandbox-strict", Mode: authjwt.Strict},
			JWKSURL:  testsupport.SandboxURL + "/.well-known/jwks.json", RootCAs: roots,
			IntrospectionURL: testsupport.SandboxURL + "/api/v1/internal/auth/token/introspect",
			ClientID:         "sandbox-consumer", ClientSecret: strings.Repeat("A", 43),
		})
		if err != nil {
			t.Fatal("negative consumer startup failed")
		}
		t.Cleanup(bad.Close)
		testsupport.Consume(t, bad, s.AccessToken, "sandbox.records.read", 503)
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
	})
	t.Run("native MFA issues tokens only after a fresh factor", func(t *testing.T) {
		var challenge testsupport.TokenResponse
		h := testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("admin", "accounts.users.read"), &challenge, 202)
		if challenge.AccessToken != "" || challenge.RefreshToken != "" || challenge.Binding == "" || challenge.NextStep != "mfa" || h.Get("Set-Cookie") != "" {
			t.Fatal("unrestricted or cookie-bound native challenge")
		}
		input := map[string]string{"challenge": challenge.Challenge, "binding": challenge.Binding, "code": testsupport.AdminCode(t)}
		var issued testsupport.TokenResponse
		testsupport.Request(t, api, "POST", "/api/v1/auth/native/mfa/complete", input, &issued, 200)
		testsupport.Consume(t, strict, issued.AccessToken, "accounts.users.read", 204)
		testsupport.Request(t, api, "POST", "/api/v1/auth/native/mfa/complete", input, nil, 400)
		testsupport.Request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": issued.RefreshToken}, nil, 204)
		testsupport.Consume(t, strict, issued.AccessToken, "accounts.users.read", 401)
	})

	for _, dependency := range []string{"redis", "postgres"} {
		t.Run(dependency+" outage fails closed then recovers", func(t *testing.T) {
			s := testsupport.Exchange(t, browser, "sandbox-strict")
			l := testsupport.Exchange(t, browser, "sandbox-local")
			testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
			t.Cleanup(func() { testsupport.DockerDependency(t, "start", dependency); testsupport.WaitReadiness(t, api, 200) })
			testsupport.DockerDependency(t, "stop", dependency)
			// Readiness deliberately coalesces probes for one second.
			testsupport.WaitReadiness(t, api, 503)
			testsupport.Request(t, api, "GET", "/health/live", nil, nil, 200)
			testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 503)
			testsupport.Consume(t, local, l.AccessToken, "sandbox.records.read", 204)
			testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, 503)
			testsupport.DockerDependency(t, "start", dependency)
			testsupport.WaitReadiness(t, api, 200)
			testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		})
	}
	t.Run("both modes refuse expired JWT", func(t *testing.T) {
		s := testsupport.Exchange(t, browser, "sandbox-strict")
		l := testsupport.Exchange(t, browser, "sandbox-local")
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		testsupport.Consume(t, local, l.AccessToken, "sandbox.records.read", 204)
		if l.ExpiresAt.IsZero() || time.Until(l.ExpiresAt) > 65*time.Second {
			t.Fatal("sandbox JWT lifetime must be one minute")
		}
		timer := time.NewTimer(time.Until(l.ExpiresAt.Add(100 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal("expiry wait cancelled")
		}
		testsupport.Consume(t, strict, s.AccessToken, "sandbox.records.read", 401)
		testsupport.Consume(t, local, l.AccessToken, "sandbox.records.read", 401)
	})
}

func setIssuance(t *testing.T, admin *http.Client, exchangeEnabled, nativeEnabled bool) {
	t.Helper()
	var current struct {
		Version int64          `json:"version"`
		Policy  map[string]any `json:"policy"`
	}
	testsupport.Request(t, admin, "GET", "/api/v1/admin/auth/settings", nil, &current, 200)
	current.Policy["tokenIssuance"] = map[string]bool{"sessionExchange": exchangeEnabled, "native": nativeEnabled}
	testsupport.Request(t, admin, "POST", "/api/v1/admin/auth/settings", map[string]any{"expectedVersion": current.Version, "policy": current.Policy}, nil, 200, "Origin", testsupport.SandboxURL)
}

package sandbox_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type tokenResponse struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Challenge    string    `json:"challenge"`
	Binding      string    `json:"binding"`
	NextStep     string    `json:"nextStep"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func TestJWTAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_ACCEPTANCE") != "1" {
		t.Skip("explicit live auth-sandbox test; run task sandbox:jwt")
	}
	api, roots := sandboxClient(t, false)
	admin := adminLogin(t)
	setIssuance(t, admin, true, true)
	t.Cleanup(func() { setIssuance(t, admin, true, true) })
	strict, local := newConsumer(t, roots, authjwt.Strict), newConsumer(t, roots, authjwt.Local)
	browser := userLogin(t)

	t.Run("JWKS metadata and secret-free public keys", func(t *testing.T) {
		var keys struct {
			Keys []map[string]json.RawMessage `json:"keys"`
		}
		h := request(t, api, "GET", "/.well-known/jwks.json", nil, &keys, 200)
		if len(keys.Keys) != 1 || keys.Keys[0]["d"] != nil || h.Get("ETag") == "" {
			t.Fatal("invalid public-only JWKS")
		}
		request(t, api, "GET", "/.well-known/jwks.json", nil, nil, 304, "If-None-Match", h.Get("ETag"))
		request(t, api, "HEAD", "/.well-known/jwks.json", nil, nil, 200)
	})

	t.Run("cookie exchange strict versus local revocation", func(t *testing.T) {
		browser := userLogin(t)
		s := exchange(t, browser, "sandbox-strict")
		l := exchange(t, browser, "sandbox-local")
		consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		consume(t, local, l.AccessToken, "sandbox.records.read", 204)
		consume(t, strict, s.AccessToken, "sandbox.records.write", 403)
		consume(t, strict, s.AccessToken+"x", "sandbox.records.read", 401)
		consume(t, strict, l.AccessToken, "sandbox.records.read", 401)
		consume(t, local, s.AccessToken, "sandbox.records.read", 401)
		consume(t, strict, s.AccessToken, "sandbox.records.read", 401, "Cookie", "session=ambiguous")
		request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Authorization", "Bearer "+s.AccessToken)
		request(t, browser, "POST", "/api/v1/auth/token/exchange", resource("sandbox-strict"), nil, 403, "Origin", "https://hostile.example")
		request(t, browser, "POST", "/api/v1/auth/logout", nil, nil, 204, "Origin", sandboxURL)
		consume(t, strict, s.AccessToken, "sandbox.records.read", 401)
		consume(t, local, l.AccessToken, "sandbox.records.read", 204)
	})

	t.Run("native refresh replay and independent logout", func(t *testing.T) {
		first := nativeLogin(t, api)
		consume(t, strict, first.AccessToken, "sandbox.records.read", 204)
		var next tokenResponse
		request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": first.RefreshToken}, &next, 200)
		if first.RefreshToken == next.RefreshToken || next.RefreshToken == "" {
			t.Fatal("refresh did not rotate")
		}
		consume(t, strict, next.AccessToken, "sandbox.records.read", 204)
		request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": next.RefreshToken}, nil, 429)
		request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": first.RefreshToken}, nil, 401)
		consume(t, strict, next.AccessToken, "sandbox.records.read", 401)
		request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": next.RefreshToken}, nil, 401)
		other := nativeLogin(t, api)
		consume(t, strict, other.AccessToken, "sandbox.records.read", 204)
		request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": other.RefreshToken}, nil, 204)
		consume(t, strict, other.AccessToken, "sandbox.records.read", 401)
		request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": other.RefreshToken}, nil, 204)
	})

	t.Run("issuance switches do not disable introspection or logout", func(t *testing.T) {
		s := exchange(t, browser, "sandbox-strict")
		native := nativeLogin(t, api)
		setIssuance(t, admin, false, false)
		request(t, browser, "POST", "/api/v1/auth/token/exchange", resource("sandbox-strict"), nil, 403, "Origin", sandboxURL)
		request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, 404)
		consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": native.RefreshToken}, nil, 204)
		consume(t, strict, native.AccessToken, "sandbox.records.read", 401)
		setIssuance(t, admin, true, true)
	})

	t.Run("native and introspection reject browser credentials", func(t *testing.T) {
		for _, header := range []string{"Origin", "Cookie", "Authorization"} {
			want := 400
			if header == "Origin" {
				want = 403
			}
			request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, want, header, "untrusted")
		}
		request(t, api, "OPTIONS", "/api/v1/auth/native/password/login", nil, nil, 403)
		request(t, api, "POST", "/api/v1/internal/auth/token/introspect", map[string]string{"token": "invalid"}, nil, 401)
	})
	t.Run("service credentials are not user credentials", func(t *testing.T) {
		s := exchange(t, browser, "sandbox-strict")
		bad, err := authjwt.NewConsumer(t.Context(), authjwt.ConsumerConfig{
			Expected: authjwt.Expectations{Issuer: sandboxURL, Audience: "sandbox-strict", Mode: authjwt.Strict},
			JWKSURL:  sandboxURL + "/.well-known/jwks.json", RootCAs: roots,
			IntrospectionURL: sandboxURL + "/api/v1/internal/auth/token/introspect",
			ClientID:         "sandbox-consumer", ClientSecret: strings.Repeat("A", 43),
		})
		if err != nil {
			t.Fatal("negative consumer startup failed")
		}
		t.Cleanup(bad.Close)
		consume(t, bad, s.AccessToken, "sandbox.records.read", 503)
		consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
	})
	t.Run("native MFA issues tokens only after a fresh factor", func(t *testing.T) {
		var challenge tokenResponse
		h := request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("admin", "accounts.users.read"), &challenge, 202)
		if challenge.AccessToken != "" || challenge.RefreshToken != "" || challenge.Binding == "" || challenge.NextStep != "mfa" || h.Get("Set-Cookie") != "" {
			t.Fatal("unrestricted or cookie-bound native challenge")
		}
		input := map[string]string{"challenge": challenge.Challenge, "binding": challenge.Binding, "code": adminCode(t)}
		var issued tokenResponse
		request(t, api, "POST", "/api/v1/auth/native/mfa/complete", input, &issued, 200)
		consume(t, strict, issued.AccessToken, "accounts.users.read", 204)
		request(t, api, "POST", "/api/v1/auth/native/mfa/complete", input, nil, 400)
		request(t, api, "POST", "/api/v1/auth/token/logout", map[string]string{"refreshToken": issued.RefreshToken}, nil, 204)
		consume(t, strict, issued.AccessToken, "accounts.users.read", 401)
	})

	for _, dependency := range []string{"redis", "postgres"} {
		t.Run(dependency+" outage fails closed then recovers", func(t *testing.T) {
			s := exchange(t, browser, "sandbox-strict")
			l := exchange(t, browser, "sandbox-local")
			consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
			t.Cleanup(func() { dockerDependency(t, "start", dependency); waitReadiness(t, api, 200) })
			dockerDependency(t, "stop", dependency)
			// Readiness deliberately coalesces probes for one second.
			waitReadiness(t, api, 503)
			request(t, api, "GET", "/health/live", nil, nil, 200)
			consume(t, strict, s.AccessToken, "sandbox.records.read", 503)
			consume(t, local, l.AccessToken, "sandbox.records.read", 204)
			request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), nil, 503)
			dockerDependency(t, "start", dependency)
			waitReadiness(t, api, 200)
			consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		})
	}
	t.Run("both modes refuse expired JWT", func(t *testing.T) {
		s := exchange(t, browser, "sandbox-strict")
		l := exchange(t, browser, "sandbox-local")
		consume(t, strict, s.AccessToken, "sandbox.records.read", 204)
		consume(t, local, l.AccessToken, "sandbox.records.read", 204)
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
		consume(t, strict, s.AccessToken, "sandbox.records.read", 401)
		consume(t, local, l.AccessToken, "sandbox.records.read", 401)
	})
}

func resource(audience string) map[string]any {
	return map[string]any{"audience": audience, "scope": []string{"sandbox.records.read"}}
}

func passwordInput(user, permission string) map[string]any {
	return map[string]any{"email": user + "@sandbox.example", "password": "Sandbox-" + strings.ToUpper(user[:1]) + user[1:] + "-2026!", "audience": "sandbox-strict", "scope": []string{permission}}
}

func userLogin(t *testing.T) *http.Client {
	t.Helper()
	client, _ := sandboxClient(t, true)
	request(t, client, "POST", "/api/v1/auth/login/email", map[string]string{"email": "ivan@sandbox.example", "password": "Sandbox-Ivan-2026!"}, nil, 200, "Origin", sandboxURL)
	return client
}

func adminLogin(t *testing.T) *http.Client {
	t.Helper()
	client, _ := sandboxClient(t, true)
	var challenge tokenResponse
	request(t, client, "POST", "/api/v1/admin/auth/login/email", map[string]string{"email": "admin@sandbox.example", "password": "Sandbox-Admin-2026!"}, &challenge, 202, "Origin", sandboxURL)
	request(t, client, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": adminCode(t)}, nil, 200, "Origin", sandboxURL)
	return client
}

func adminCode(t *testing.T) string {
	t.Helper()
	var setup struct {
		Secret string `json:"secret"`
	}
	privateJSON(t, "admin-setup.json", &setup)
	// A prior manual/test login may already have consumed the current step.
	timer := time.NewTimer(time.Until(time.Now().Truncate(30 * time.Second).Add(31 * time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("MFA wait cancelled")
	}
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatal("invalid synthetic TOTP fixture")
	}
	return code
}

func setIssuance(t *testing.T, admin *http.Client, exchangeEnabled, nativeEnabled bool) {
	t.Helper()
	var current struct {
		Version int64          `json:"version"`
		Policy  map[string]any `json:"policy"`
	}
	request(t, admin, "GET", "/api/v1/admin/auth/settings", nil, &current, 200)
	current.Policy["tokenIssuance"] = map[string]bool{"sessionExchange": exchangeEnabled, "native": nativeEnabled}
	request(t, admin, "POST", "/api/v1/admin/auth/settings", map[string]any{"expectedVersion": current.Version, "policy": current.Policy}, nil, 200, "Origin", sandboxURL)
}

func exchange(t *testing.T, browser *http.Client, audience string) tokenResponse {
	t.Helper()
	var token tokenResponse
	h := request(t, browser, "POST", "/api/v1/auth/token/exchange", resource(audience), &token, 200, "Origin", sandboxURL)
	if token.AccessToken == "" || token.RefreshToken != "" || h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid exchange output")
	}
	return token
}

func nativeLogin(t *testing.T, api *http.Client) tokenResponse {
	t.Helper()
	var token tokenResponse
	h := request(t, api, "POST", "/api/v1/auth/native/password/login", passwordInput("ivan", "sandbox.records.read"), &token, 200)
	if token.AccessToken == "" || token.RefreshToken == "" || h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid native output")
	}
	// Never print opaque tokens, even on a failed fixture.
	if _, err := base64.RawURLEncoding.DecodeString(token.RefreshToken); err != nil {
		t.Fatal("noncanonical refresh fixture")
	}
	return token
}

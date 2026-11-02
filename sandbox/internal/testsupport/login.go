package testsupport

import (
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

type TokenResponse struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	Challenge    string    `json:"challenge"`
	Binding      string    `json:"binding"`
	NextStep     string    `json:"nextStep"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func Resource(audience string) map[string]any {
	return map[string]any{"audience": audience, "scope": []string{"sandbox.records.read"}}
}

func UserLogin(t *testing.T) *http.Client {
	t.Helper()
	client, _ := SandboxClient(t, true)
	Request(t, client, "POST", "/api/v1/auth/login/email", map[string]string{"email": "ivan@sandbox.example", "password": "Sandbox-Ivan-2026!"}, nil, 200, "Origin", SandboxURL)
	return client
}

func AdminLogin(t *testing.T) *http.Client {
	t.Helper()
	client, _ := SandboxClient(t, true)
	var challenge TokenResponse
	Request(t, client, "POST", "/api/v1/admin/auth/login/email", map[string]string{"email": "admin@sandbox.example", "password": "Sandbox-Admin-2026!"}, &challenge, 202, "Origin", SandboxURL)
	Request(t, client, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": AdminCode(t)}, nil, 200, "Origin", SandboxURL)
	return client
}

func AdminCode(t *testing.T) string {
	t.Helper()
	var setup struct {
		Secret string `json:"secret"`
	}
	PrivateJSON(t, "admin-setup.json", &setup)
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

func Exchange(t *testing.T, browser *http.Client, audience string) TokenResponse {
	t.Helper()
	var token TokenResponse
	h := Request(t, browser, "POST", "/api/v1/auth/token/exchange", Resource(audience), &token, 200, "Origin", SandboxURL)
	if token.AccessToken == "" || token.RefreshToken != "" || h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("invalid exchange output")
	}
	return token
}

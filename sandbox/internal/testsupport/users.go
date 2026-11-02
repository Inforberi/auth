package testsupport

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const AdminTestPassword = "Sandbox-Users-Test-2026!"

type AdminAccount struct {
	ID    string
	Email string
}

type AdminRole struct {
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Version     int64    `json:"version"`
	System      bool     `json:"system"`
	MFARequired bool     `json:"mfaRequired"`
	Permissions []string `json:"permissions"`
}

type AdminUserCard struct {
	ID                        string      `json:"id"`
	Status                    string      `json:"status"`
	AuthVersion               int64       `json:"authVersion"`
	AccessVersion             int64       `json:"accessVersion"`
	EmailVerified             bool        `json:"emailVerified"`
	PasswordConfigured        bool        `json:"passwordConfigured"`
	TemporaryPasswordRequired bool        `json:"temporaryPasswordRequired"`
	DeletedAt                 *time.Time  `json:"deletedAt"`
	Roles                     []AdminRole `json:"roles"`
}

func AdminCommand(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func ExpectAdminError(t *testing.T, client *http.Client, method, path string, input any, status int, code string) {
	t.Helper()
	var result struct {
		Code string `json:"code"`
	}
	Request(t, client, method, path, input, &result, status, "Origin", SandboxURL)
	if result.Code != code {
		t.Fatalf("%s %s: got code %s, want %s", method, path, result.Code, code)
	}
}

func ReadAdminUser(t *testing.T, admin *http.Client, id string) AdminUserCard {
	t.Helper()
	var card AdminUserCard
	Request(t, admin, "GET", "/api/v1/admin/users/"+id, nil, &card, 200)
	if card.ID != id || card.AuthVersion < 1 || card.AccessVersion < 1 {
		t.Fatal("invalid user card")
	}
	return card
}

func LoginAdminTestUser(t *testing.T, account AdminAccount) *http.Client {
	t.Helper()
	client, _ := SandboxClient(t, true)
	Request(t, client, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": AdminTestPassword}, nil, 200, "Origin", SandboxURL)
	return client
}

func AssignmentBody(role AdminRole, card AdminUserCard) map[string]any {
	return map[string]any{"expectedRoleVersion": role.Version, "expectedAccessVersion": card.AccessVersion}
}

func RoleUpdate(role AdminRole, permissions []string) map[string]any {
	return map[string]any{"key": role.Key, "name": "Sandbox reader", "permissions": permissions, "expectedVersion": role.Version}
}

func AssertUnexpired(t *testing.T, tokens ...TokenResponse) {
	t.Helper()
	for _, token := range tokens {
		if time.Until(token.ExpiresAt) < 15*time.Second {
			t.Fatal("expiry would obscure the key/trust decision")
		}
	}
}

func WaitSecurityUntil(t *testing.T, deadline time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			return
		case <-ticker.C:
			t.Logf("real security deadline: %s remaining", time.Until(deadline).Round(time.Second))
		case <-t.Context().Done():
			t.Fatal("security deadline wait cancelled")
		}
	}
}

func AdminReadToken(t *testing.T, client *http.Client) TokenResponse {
	t.Helper()
	var token TokenResponse
	Request(t, client, "POST", "/api/v1/auth/token/exchange", map[string]any{"audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}, &token, 200, "Origin", SandboxURL)
	if token.AccessToken == "" {
		t.Fatal("missing role-scoped access token")
	}
	return token
}

func AssertNoLifecycleSession(t *testing.T, headers http.Header) {
	t.Helper()
	if headers.Get("Set-Cookie") != "" || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("lifecycle operation created a session or cacheable response")
	}
}

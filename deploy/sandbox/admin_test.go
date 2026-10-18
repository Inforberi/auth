package sandbox_test

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const adminTestPassword = "Sandbox-Users-Test-2026!"

type adminAccount struct {
	ID    string
	Email string
}

type adminRole struct {
	ID          string   `json:"id"`
	Key         string   `json:"key"`
	Version     int64    `json:"version"`
	System      bool     `json:"system"`
	MFARequired bool     `json:"mfaRequired"`
	Permissions []string `json:"permissions"`
}

type adminUserCard struct {
	ID                        string      `json:"id"`
	Status                    string      `json:"status"`
	AuthVersion               int64       `json:"authVersion"`
	AccessVersion             int64       `json:"accessVersion"`
	EmailVerified             bool        `json:"emailVerified"`
	PasswordConfigured        bool        `json:"passwordConfigured"`
	TemporaryPasswordRequired bool        `json:"temporaryPasswordRequired"`
	DeletedAt                 *time.Time  `json:"deletedAt"`
	Roles                     []adminRole `json:"roles"`
}

func TestAdminAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_ADMIN") != "1" {
		t.Skip("explicit HTTPS users/roles acceptance; run task sandbox:admin")
	}
	api, roots := sandboxClient(t, false)
	enableAdminSandbox(t, api)
	checkAdminAcceptance(t, api, roots)
}

func enableAdminSandbox(t *testing.T, api *http.Client) {
	t.Helper()
	assertKeyIDs(t, api, "sandbox-1")
	dir, err := os.MkdirTemp(sandboxDirectory(t), "admin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		redeploySandboxAPI(t, api, "")
		if err := os.RemoveAll(dir); err != nil {
			t.Error("cannot remove generated administrative test override")
		}
	})
	override := filepath.Join(dir, "compose.json")
	writeJSON(t, override, map[string]any{"services": map[string]any{"api": map[string]any{
		"environment": map[string]string{"INVITATIONS_ENABLED": "true", "TEMPORARY_PASSWORD_ENABLED": "true", "INVITATION_URL": sandboxURL + "/activate-account"},
	}}})
	redeploySandboxAPI(t, api, override)
}

func checkAdminAcceptance(t *testing.T, api *http.Client, roots *x509.CertPool) {
	t.Helper()
	suffix := strings.ReplaceAll(adminCommand(t), "-", "")
	roleInput := map[string]any{"key": "sandbox_reader_" + suffix, "name": "Sandbox reader", "permissions": []string{"accounts.users.read"}}

	t.Log("unfinished/public administrator proof cannot perform management mutations")
	public, _ := sandboxClient(t, true)
	var challenge tokenResponse
	request(t, public, "POST", "/api/v1/auth/login/email", map[string]string{"email": "admin@sandbox.example", "password": "Sandbox-Admin-2026!"}, &challenge, 202, "Origin", sandboxURL)
	expectAdminError(t, public, "POST", "/api/v1/admin/roles", roleInput, 401, "unauthorized")
	request(t, public, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": adminCode(t)}, nil, 200, "Origin", sandboxURL)
	expectAdminError(t, public, "POST", "/api/v1/admin/roles", roleInput, 403, "fresh_auth_required")
	admin := adminLogin(t)
	checkLastAdministrator(t, admin)

	t.Log("invitation activation and temporary-password setup through real mail/API")
	invited := activateAdminInvitation(t, admin, api, suffix)
	temporary := activateAdminTemporary(t, admin, api, suffix)
	checkAdminDirectory(t, admin, invited, temporary)

	t.Log("custom role assignment, revisions, revocation, strict JWT and status lifecycle")
	strict := newConsumer(t, roots, "strict")
	checkAdminAccess(t, admin, api, strict, invited, roleInput)
	t.Logf("synthetic accounts retained without elevated access: invited=%s temporary=%s", invited.ID, temporary.ID)
}

func adminCommand(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func expectAdminError(t *testing.T, client *http.Client, method, path string, input any, status int, code string) {
	t.Helper()
	var result struct {
		Code string `json:"code"`
	}
	request(t, client, method, path, input, &result, status, "Origin", sandboxURL)
	if result.Code != code {
		t.Fatalf("%s %s: got code %s, want %s", method, path, result.Code, code)
	}
}

func readAdminUser(t *testing.T, admin *http.Client, id string) adminUserCard {
	t.Helper()
	var card adminUserCard
	request(t, admin, "GET", "/api/v1/admin/users/"+id, nil, &card, 200)
	if card.ID != id || card.AuthVersion < 1 || card.AccessVersion < 1 {
		t.Fatal("invalid user card")
	}
	return card
}

func loginAdminTestUser(t *testing.T, account adminAccount) *http.Client {
	t.Helper()
	client, _ := sandboxClient(t, true)
	request(t, client, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": adminTestPassword}, nil, 200, "Origin", sandboxURL)
	return client
}

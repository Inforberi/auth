package sandbox_test

import (
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"testing"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func TestAdminAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_ADMIN") != "1" {
		t.Skip("explicit HTTPS users/roles acceptance; run task sandbox:admin")
	}
	api, roots := testsupport.SandboxClient(t, false)
	testsupport.EnableAdminSandbox(t, api)
	checkAdminAcceptance(t, api, roots)
}

func checkAdminAcceptance(t *testing.T, api *http.Client, roots *x509.CertPool) {
	t.Helper()
	suffix := strings.ReplaceAll(testsupport.AdminCommand(t), "-", "")
	roleInput := map[string]any{"key": "sandbox_reader_" + suffix, "name": "Sandbox reader", "permissions": []string{"accounts.users.read"}}

	t.Log("unfinished/public administrator proof cannot perform management mutations")
	public, _ := testsupport.SandboxClient(t, true)
	var challenge testsupport.TokenResponse
	testsupport.Request(t, public, "POST", "/api/v1/auth/login/email", map[string]string{"email": "admin@sandbox.example", "password": "Sandbox-Admin-2026!"}, &challenge, 202, "Origin", testsupport.SandboxURL)
	testsupport.ExpectAdminError(t, public, "POST", "/api/v1/admin/roles", roleInput, 401, "unauthorized")
	testsupport.Request(t, public, "POST", "/api/v1/auth/mfa/login/complete", map[string]string{"challenge": challenge.Challenge, "code": testsupport.AdminCode(t)}, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.ExpectAdminError(t, public, "POST", "/api/v1/admin/roles", roleInput, 403, "fresh_auth_required")
	admin := testsupport.AdminLogin(t)
	checkLastAdministrator(t, admin)

	t.Log("invitation activation and temporary-password setup through real mail/API")
	invited := testsupport.ActivateAdminInvitation(t, admin, api, suffix)
	temporary := activateAdminTemporary(t, admin, api, suffix)
	checkAdminDirectory(t, admin, invited, temporary)

	t.Log("custom role assignment, revisions, revocation, strict JWT and status lifecycle")
	strict := testsupport.NewConsumer(t, roots, "strict")
	checkAdminAccess(t, admin, api, strict, invited, roleInput)
	t.Logf("synthetic accounts retained without elevated access: invited=%s temporary=%s", invited.ID, temporary.ID)
}

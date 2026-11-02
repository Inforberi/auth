package sandbox_test

import (
	"os"
	"strings"
	"testing"
	"time"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func TestSecurityAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_SECURITY") != "1" {
		t.Skip("explicit HTTPS freshness/MFA acceptance; run task sandbox:security")
	}
	api, roots := testsupport.SandboxClient(t, false)
	testsupport.EnableAdminSandbox(t, api)
	admin := testsupport.AdminLogin(t)
	// Both proofs were committed no later than the completed HTTPS login response.
	staleAfter := time.Now().Add(5*time.Minute + 5*time.Second)
	suffix := strings.ReplaceAll(testsupport.AdminCommand(t), "-", "")
	if !t.Run("required role MFA", func(t *testing.T) {
		checkRoleMFA(t, admin, api, testsupport.NewConsumer(t, roots, "strict"), suffix)
	}) {
		t.Fatal("role MFA failed; freshness acceptance not run")
	}
	t.Run("five-minute proof expiry", func(t *testing.T) {
		checkFreshAuthExpiry(t, admin, staleAfter, suffix)
	})
}

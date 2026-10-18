package sandbox_test

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSecurityAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_SECURITY") != "1" {
		t.Skip("explicit HTTPS freshness/MFA acceptance; run task sandbox:security")
	}
	api, roots := sandboxClient(t, false)
	enableAdminSandbox(t, api)
	admin := adminLogin(t)
	// Both proofs were committed no later than the completed HTTPS login response.
	staleAfter := time.Now().Add(5*time.Minute + 5*time.Second)
	suffix := strings.ReplaceAll(adminCommand(t), "-", "")
	if !t.Run("required role MFA", func(t *testing.T) {
		checkRoleMFA(t, admin, api, newConsumer(t, roots, "strict"), suffix)
	}) {
		t.Fatal("role MFA failed; freshness acceptance not run")
	}
	t.Run("five-minute proof expiry", func(t *testing.T) {
		checkFreshAuthExpiry(t, admin, staleAfter, suffix)
	})
}

func waitSecurityUntil(t *testing.T, deadline time.Time) {
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

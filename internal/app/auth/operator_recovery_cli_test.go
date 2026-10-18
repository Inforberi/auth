package auth

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

func operatorRecoveryCommand(t *testing.T, login string, args []string, confirmation string, password, success bool) {
	t.Helper()
	program := os.Getenv("AUTH_OPERATOR_TEST_CLI")
	child := exec.CommandContext(t.Context(), program, args...)
	child.Env = []string{"AUTH_RECOVERY_DATABASE_URL=postgres://" + login + ":fixture-offline-only@127.0.0.1/auth_platform_test?sslmode=disable"}
	child.Stdin = strings.NewReader(confirmation + "\n")
	if password {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		if _, err := io.WriteString(w, "PlatformClilogin4\n"); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		child.ExtraFiles = []*os.File{r}
	}
	output, err := child.CombinedOutput()
	if (err == nil) != success {
		t.Fatalf("recovery CLI outcome success=%v: %v", success, err)
	}
	for _, secret := range []string{"fixture-offline-only", "PlatformClilogin4", "postgres://"} {
		if strings.Contains(string(output), secret) {
			t.Fatal("recovery CLI leaked a credential")
		}
	}
}

func operatorPasswordCLI(t *testing.T, realm string, user accountdomain.UserID, version int64) {
	t.Helper()
	args := []string{"-environment", "test", "-user", string(user), "-reason", "fixture-cli-incident"}
	operatorRecoveryCommand(t, "platform_password_test", args, "", false, false)
	args = append(args, "-platform-realm", "11111111-1111-4111-8111-111111111111")
	operatorRecoveryCommand(t, "platform_password_test", args, "", false, false)
	args[len(args)-1] = realm
	confirmation := fmt.Sprintf("RESET test 127.0.0.1:5432[platform=%s]/auth_platform_test %s v%d", realm, user, version)
	operatorRecoveryCommand(t, "platform_password_test", args, confirmation, true, true)
}

func operatorMFACLI(t *testing.T, realm string, decision mfadomain.RecoveryDecision) {
	t.Helper()
	args := []string{"mfa-approve", "-environment", "test", "-user", string(decision.UserID), "-request", decision.RequestID, "-reason", decision.Reason, "-platform-realm", realm}
	confirmation := fmt.Sprintf("MFA-APPROVE test 127.0.0.1:5432[platform=%s]/auth_platform_test %s %s v%d", realm, decision.UserID, decision.RequestID, decision.ExpectedVersion)
	operatorRecoveryCommand(t, "platform_password_test", args, confirmation, false, false)
	operatorRecoveryCommand(t, "platform_mfa_test", args, confirmation, false, true)
}

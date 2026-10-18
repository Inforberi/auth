package sandbox_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLifecycleAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_LIFECYCLE") != "1" {
		t.Skip("explicit HTTPS reissue/deletion acceptance; run task sandbox:lifecycle")
	}
	api, roots := sandboxClient(t, false)
	enableAdminSandbox(t, api)
	admin := adminLogin(t)
	suffix := strings.ReplaceAll(adminCommand(t), "-", "")
	invited, oldInvitation := pendingLifecycleInvitation(t, admin, suffix)
	temporary, oldPassword, oldSetup := pendingLifecycleTemporary(t, admin, api, suffix)
	invitationPath := "/api/v1/admin/users/" + invited.ID + "/invitation"
	temporaryPath := "/api/v1/admin/users/" + temporary.ID + "/temporary-password"
	invitationCommand := map[string]string{"idempotencyKey": adminCommand(t)}
	temporaryCommand := map[string]string{"idempotencyKey": adminCommand(t)}
	expectAdminError(t, admin, "POST", invitationPath, invitationCommand, 409, "issuance_cooldown")
	expectAdminError(t, admin, "POST", temporaryPath, temporaryCommand, 409, "issuance_cooldown")

	t.Log("both immediate reissues denied; waiting for the real one-minute cooldown")
	timer := time.NewTimer(61 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("cancelled during cooldown")
	}
	checkInvitationReissue(t, admin, api, invited, oldInvitation, invitationCommand)
	checkTemporaryReissue(t, admin, api, temporary, oldPassword, oldSetup, temporaryCommand)
	t.Log("reissues invalidate old proofs; replay does not issue another secret")
	consumer := newConsumer(t, roots, "strict")
	checkLifecycleDeletion(t, admin, api, consumer, invited, temporary)
	t.Log("new synthetic accounts deleted; old sessions/JWT/native refresh rejected")
}

func assertNoLifecycleSession(t *testing.T, headers http.Header) {
	t.Helper()
	if headers.Get("Set-Cookie") != "" || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("lifecycle operation created a session or cacheable response")
	}
}

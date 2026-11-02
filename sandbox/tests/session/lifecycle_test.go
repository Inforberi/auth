package sandbox_test

import (
	"os"
	"strings"
	"testing"
	"time"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func TestLifecycleAcceptance(t *testing.T) {
	if os.Getenv("AUTH_SANDBOX_LIFECYCLE") != "1" {
		t.Skip("explicit HTTPS reissue/deletion acceptance; run task sandbox:lifecycle")
	}
	api, roots := testsupport.SandboxClient(t, false)
	testsupport.EnableAdminSandbox(t, api)
	admin := testsupport.AdminLogin(t)
	suffix := strings.ReplaceAll(testsupport.AdminCommand(t), "-", "")
	invited, oldInvitation := testsupport.PendingLifecycleInvitation(t, admin, suffix)
	temporary, oldPassword, oldSetup := testsupport.PendingLifecycleTemporary(t, admin, api, suffix)
	invitationPath := "/api/v1/admin/users/" + invited.ID + "/invitation"
	temporaryPath := "/api/v1/admin/users/" + temporary.ID + "/temporary-password"
	invitationCommand := map[string]string{"idempotencyKey": testsupport.AdminCommand(t)}
	temporaryCommand := map[string]string{"idempotencyKey": testsupport.AdminCommand(t)}
	testsupport.ExpectAdminError(t, admin, "POST", invitationPath, invitationCommand, 409, "issuance_cooldown")
	testsupport.ExpectAdminError(t, admin, "POST", temporaryPath, temporaryCommand, 409, "issuance_cooldown")

	t.Log("both immediate reissues denied; waiting for the real one-minute cooldown")
	timer := time.NewTimer(61 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("cancelled during cooldown")
	}
	testsupport.CheckInvitationReissue(t, admin, api, invited, oldInvitation, invitationCommand)
	testsupport.CheckTemporaryReissue(t, admin, api, temporary, oldPassword, oldSetup, temporaryCommand)
	t.Log("reissues invalidate old proofs; replay does not issue another secret")
	consumer := testsupport.NewConsumer(t, roots, "strict")
	checkLifecycleDeletion(t, admin, api, consumer, invited, temporary)
	t.Log("new synthetic accounts deleted; old sessions/JWT/native refresh rejected")
}

package testsupport

import (
	"net/http"
	"testing"
)

func PendingLifecycleInvitation(t *testing.T, admin *http.Client, suffix string) (AdminAccount, string) {
	t.Helper()
	account := AdminAccount{Email: "reinvite-" + suffix + "@sandbox.example"}
	var issued struct{ UserID string }
	input := map[string]any{"idempotencyKey": AdminCommand(t), "email": account.Email, "invite": true}
	Request(t, admin, "POST", "/api/v1/admin/users", input, &issued, 201, "Origin", SandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || ReadAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("invitation did not create a pending account")
	}
	return account, InvitationMailToken(t, account.Email)
}

func CheckInvitationReissue(t *testing.T, admin, api *http.Client, account AdminAccount, previous string, command map[string]string) {
	t.Helper()
	path := "/api/v1/admin/users/" + account.ID + "/invitation"
	var first, replay struct {
		UserID string
		Reused bool
	}
	AssertNoLifecycleSession(t, Request(t, admin, "POST", path, command, &first, 200, "Origin", SandboxURL))
	AssertNoLifecycleSession(t, Request(t, admin, "POST", path, command, &replay, 200, "Origin", SandboxURL))
	if first.UserID != account.ID || first.Reused || replay.UserID != account.ID || !replay.Reused {
		t.Fatal("invitation reissue changed owner or failed idempotency")
	}
	activation := map[string]string{"token": previous, "password": AdminTestPassword, "confirmPassword": AdminTestPassword}
	ExpectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	if ReadAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("replaced invitation activated the account")
	}
	activation["token"] = InvitationMailToken(t, account.Email, previous)
	AssertNoLifecycleSession(t, Request(t, api, "POST", "/api/v1/auth/invitations/activate", activation, nil, 200, "Origin", SandboxURL))
	ExpectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	card := ReadAdminUser(t, admin, account.ID)
	if card.Status != "active" || !card.EmailVerified || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("reissued invitation activation violated account boundaries")
	}
}

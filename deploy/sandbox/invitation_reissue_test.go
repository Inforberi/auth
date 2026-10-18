package sandbox_test

import (
	"net/http"
	"testing"
)

func pendingLifecycleInvitation(t *testing.T, admin *http.Client, suffix string) (adminAccount, string) {
	t.Helper()
	account := adminAccount{Email: "reinvite-" + suffix + "@sandbox.example"}
	var issued struct{ UserID string }
	input := map[string]any{"idempotencyKey": adminCommand(t), "email": account.Email, "invite": true}
	request(t, admin, "POST", "/api/v1/admin/users", input, &issued, 201, "Origin", sandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || readAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("invitation did not create a pending account")
	}
	return account, invitationMailToken(t, account.Email)
}

func checkInvitationReissue(t *testing.T, admin, api *http.Client, account adminAccount, previous string, command map[string]string) {
	t.Helper()
	path := "/api/v1/admin/users/" + account.ID + "/invitation"
	var first, replay struct {
		UserID string
		Reused bool
	}
	assertNoLifecycleSession(t, request(t, admin, "POST", path, command, &first, 200, "Origin", sandboxURL))
	assertNoLifecycleSession(t, request(t, admin, "POST", path, command, &replay, 200, "Origin", sandboxURL))
	if first.UserID != account.ID || first.Reused || replay.UserID != account.ID || !replay.Reused {
		t.Fatal("invitation reissue changed owner or failed idempotency")
	}
	activation := map[string]string{"token": previous, "password": adminTestPassword, "confirmPassword": adminTestPassword}
	expectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	if readAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("replaced invitation activated the account")
	}
	activation["token"] = invitationMailToken(t, account.Email, previous)
	assertNoLifecycleSession(t, request(t, api, "POST", "/api/v1/auth/invitations/activate", activation, nil, 200, "Origin", sandboxURL))
	expectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	card := readAdminUser(t, admin, account.ID)
	if card.Status != "active" || !card.EmailVerified || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("reissued invitation activation violated account boundaries")
	}
}

package testsupport

import (
	"net/http"
	"testing"
)

func ActivateAdminInvitation(t *testing.T, admin, api *http.Client, suffix string) AdminAccount {
	t.Helper()
	account := AdminAccount{Email: "invite-" + suffix + "@sandbox.example"}
	input := map[string]any{"idempotencyKey": AdminCommand(t), "email": account.Email, "invite": true}
	var issued struct {
		UserID string `json:"userId"`
		Reused bool   `json:"reused"`
	}
	Request(t, admin, "POST", "/api/v1/admin/users", input, &issued, 201, "Origin", SandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Reused {
		t.Fatal("invalid first invitation issuance")
	}
	var replay struct {
		UserID string `json:"userId"`
		Reused bool   `json:"reused"`
	}
	Request(t, admin, "POST", "/api/v1/admin/users", input, &replay, 200, "Origin", SandboxURL)
	if replay.UserID != account.ID || !replay.Reused {
		t.Fatal("invitation replay created another account")
	}
	if card := ReadAdminUser(t, admin, account.ID); card.Status != "pending" || card.PasswordConfigured || card.EmailVerified {
		t.Fatal("invitation granted access before activation")
	}
	token := InvitationMailToken(t, account.Email)
	// URL fragments never reach HTTP; GET of the future frontend must not activate.
	Request(t, api, "GET", "/activate-account", nil, nil, 404)
	if ReadAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("opening the invitation link activated an account")
	}
	activation := map[string]string{"token": token, "password": AdminTestPassword, "confirmPassword": AdminTestPassword}
	h := Request(t, api, "POST", "/api/v1/auth/invitations/activate", activation, nil, 200, "Origin", SandboxURL)
	if h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("activation created a session or cacheable response")
	}
	ExpectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	card := ReadAdminUser(t, admin, account.ID)
	if card.Status != "active" || !card.EmailVerified || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("invitation activation did not preserve the account boundary")
	}
	return account
}

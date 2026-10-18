package sandbox_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func activateAdminInvitation(t *testing.T, admin, api *http.Client, suffix string) adminAccount {
	t.Helper()
	account := adminAccount{Email: "invite-" + suffix + "@sandbox.example"}
	input := map[string]any{"idempotencyKey": adminCommand(t), "email": account.Email, "invite": true}
	var issued struct {
		UserID string `json:"userId"`
		Reused bool   `json:"reused"`
	}
	request(t, admin, "POST", "/api/v1/admin/users", input, &issued, 201, "Origin", sandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Reused {
		t.Fatal("invalid first invitation issuance")
	}
	var replay struct {
		UserID string `json:"userId"`
		Reused bool   `json:"reused"`
	}
	request(t, admin, "POST", "/api/v1/admin/users", input, &replay, 200, "Origin", sandboxURL)
	if replay.UserID != account.ID || !replay.Reused {
		t.Fatal("invitation replay created another account")
	}
	if card := readAdminUser(t, admin, account.ID); card.Status != "pending" || card.PasswordConfigured || card.EmailVerified {
		t.Fatal("invitation granted access before activation")
	}
	token := invitationMailToken(t, account.Email)
	// URL fragments never reach HTTP; GET of the future frontend must not activate.
	request(t, api, "GET", "/activate-account", nil, nil, 404)
	if readAdminUser(t, admin, account.ID).Status != "pending" {
		t.Fatal("opening the invitation link activated an account")
	}
	activation := map[string]string{"token": token, "password": adminTestPassword, "confirmPassword": adminTestPassword}
	h := request(t, api, "POST", "/api/v1/auth/invitations/activate", activation, nil, 200, "Origin", sandboxURL)
	if h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("activation created a session or cacheable response")
	}
	expectAdminError(t, api, "POST", "/api/v1/auth/invitations/activate", activation, 400, "invalid_invitation")
	card := readAdminUser(t, admin, account.ID)
	if card.Status != "active" || !card.EmailVerified || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("invitation activation did not preserve the account boundary")
	}
	return account
}

func activateAdminTemporary(t *testing.T, admin, api *http.Client, suffix string) adminAccount {
	t.Helper()
	account := adminAccount{Email: "temporary-" + suffix + "@sandbox.example"}
	input := map[string]string{"idempotencyKey": adminCommand(t), "email": account.Email}
	var issued struct {
		UserID    string    `json:"userId"`
		Password  string    `json:"password"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	h := request(t, admin, "POST", "/api/v1/admin/users/temporary-password", input, &issued, 201, "Origin", sandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Password == "" || !issued.ExpiresAt.After(time.Now()) || h.Get("Cache-Control") != "no-store" || h.Get("Set-Cookie") != "" {
		t.Fatal("invalid one-time temporary-password response")
	}
	var replay map[string]json.RawMessage
	request(t, admin, "POST", "/api/v1/admin/users/temporary-password", input, &replay, 200, "Origin", sandboxURL)
	var owner string
	if json.Unmarshal(replay["userId"], &owner) != nil || owner != account.ID || string(replay["reused"]) != "true" || replay["password"] != nil || replay["expiresAt"] != nil {
		t.Fatal("temporary replay exposed secret/expiry or changed owner")
	}
	credentials := map[string]string{"email": account.Email, "password": issued.Password}
	expectAdminError(t, api, "POST", "/api/v1/auth/login/email", credentials, 400, "invalid_credentials")
	var setup struct{ Token, Status string }
	h = request(t, api, "POST", "/api/v1/auth/temporary-password/login", credentials, &setup, 200, "Origin", sandboxURL)
	if setup.Token == "" || setup.Status != "password_change_required" || h.Get("Set-Cookie") != "" {
		t.Fatal("temporary login created unrestricted access")
	}
	request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401)
	var samePassword struct {
		Code string `json:"code"`
	}
	request(t, api, "POST", "/api/v1/auth/temporary-password/complete", map[string]string{"token": setup.Token, "password": issued.Password, "confirmPassword": issued.Password}, &samePassword, 400, "Origin", sandboxURL)
	// Random temporary secrets need not meet the composition policy for chosen passwords.
	if samePassword.Code != "same_password" && samePassword.Code != "password_policy" {
		t.Fatal("temporary password was not rejected as a permanent password")
	}
	complete := map[string]string{"token": setup.Token, "password": adminTestPassword, "confirmPassword": adminTestPassword}
	h = request(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, nil, 200, "Origin", sandboxURL)
	if h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("password setup created a session or cacheable response")
	}
	expectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	card := readAdminUser(t, admin, account.ID)
	if card.Status != "active" || card.EmailVerified || !card.PasswordConfigured || card.TemporaryPasswordRequired || len(card.Roles) != 0 {
		t.Fatal("temporary setup verified email, granted roles or left a pending account")
	}
	expectAdminError(t, api, "POST", "/api/v1/auth/login/email", credentials, 400, "invalid_credentials")
	client := loginAdminTestUser(t, account)
	var access struct {
		Permissions []string `json:"permissions"`
	}
	request(t, client, "GET", "/api/v1/auth/access", nil, &access, 200)
	if len(access.Permissions) != 0 {
		t.Fatal("temporary setup implicitly granted permissions")
	}
	return account
}

func checkAdminDirectory(t *testing.T, admin *http.Client, accounts ...adminAccount) {
	t.Helper()
	for _, account := range accounts {
		var page struct {
			Users []adminUserCard `json:"users"`
		}
		request(t, admin, "GET", "/api/v1/admin/users?limit=1&status=active&email="+url.QueryEscape(account.Email), nil, &page, 200)
		if len(page.Users) != 1 || page.Users[0].ID != account.ID {
			t.Fatal("exact email/status filter returned the wrong user")
		}
	}
	var first struct {
		Users      []adminUserCard `json:"users"`
		NextCursor string          `json:"nextCursor"`
	}
	request(t, admin, "GET", "/api/v1/admin/users?limit=1", nil, &first, 200)
	var second struct {
		Users []adminUserCard `json:"users"`
	}
	if len(first.Users) != 1 || first.NextCursor == "" {
		t.Fatal("missing bounded directory cursor")
	}
	request(t, admin, "GET", "/api/v1/admin/users?limit=1&before="+url.QueryEscape(first.NextCursor), nil, &second, 200)
	if len(second.Users) != 1 || first.Users[0].ID == second.Users[0].ID {
		t.Fatal("directory cursor repeated a user")
	}
}

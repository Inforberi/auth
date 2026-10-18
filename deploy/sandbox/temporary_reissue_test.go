package sandbox_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func pendingLifecycleTemporary(t *testing.T, admin, api *http.Client, suffix string) (adminAccount, string, string) {
	t.Helper()
	account := adminAccount{Email: "retemporary-" + suffix + "@sandbox.example"}
	var issued struct{ UserID, Password string }
	request(t, admin, "POST", "/api/v1/admin/users/temporary-password", map[string]string{"idempotencyKey": adminCommand(t), "email": account.Email}, &issued, 201, "Origin", sandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Password == "" {
		t.Fatal("missing temporary account/secret")
	}
	var setup struct{ Token string }
	assertNoLifecycleSession(t, request(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": issued.Password}, &setup, 200, "Origin", sandboxURL))
	if setup.Token == "" {
		t.Fatal("missing pending setup proof")
	}
	return account, issued.Password, setup.Token
}

func checkTemporaryReissue(t *testing.T, admin, api *http.Client, account adminAccount, oldPassword, oldSetup string, command map[string]string) {
	t.Helper()
	before := readAdminUser(t, admin, account.ID)
	path := "/api/v1/admin/users/" + account.ID + "/temporary-password"
	var issued struct {
		UserID, Password string
		Reused           bool
		ExpiresAt        time.Time
	}
	assertNoLifecycleSession(t, request(t, admin, "POST", path, command, &issued, 200, "Origin", sandboxURL))
	if issued.UserID != account.ID || issued.Reused || issued.Password == "" || issued.Password == oldPassword || !issued.ExpiresAt.After(time.Now()) {
		t.Fatal("invalid replacement temporary credential")
	}
	var replay map[string]json.RawMessage
	assertNoLifecycleSession(t, request(t, admin, "POST", path, command, &replay, 200, "Origin", sandboxURL))
	var owner string
	var expiry time.Time
	if json.Unmarshal(replay["userId"], &owner) != nil || owner != account.ID || string(replay["reused"]) != "true" || replay["password"] != nil || json.Unmarshal(replay["expiresAt"], &expiry) != nil || !expiry.Equal(issued.ExpiresAt) {
		t.Fatal("reissue replay exposed password or changed owner/expiry")
	}
	card := readAdminUser(t, admin, account.ID)
	if card.Status != "pending" || card.AuthVersion <= before.AuthVersion || card.EmailVerified || !card.TemporaryPasswordRequired {
		t.Fatal("reissue did not replace pending account authority")
	}
	expectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": oldPassword}, 400, "invalid_temporary_password")
	complete := map[string]string{"token": oldSetup, "password": adminTestPassword, "confirmPassword": adminTestPassword}
	expectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	var setup struct{ Token string }
	assertNoLifecycleSession(t, request(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": issued.Password}, &setup, 200, "Origin", sandboxURL))
	if setup.Token == "" || setup.Token == oldSetup {
		t.Fatal("replacement password did not yield a new setup proof")
	}
	complete["token"] = setup.Token
	assertNoLifecycleSession(t, request(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, nil, 200, "Origin", sandboxURL))
	expectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	card = readAdminUser(t, admin, account.ID)
	if card.Status != "active" || card.EmailVerified || card.TemporaryPasswordRequired || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("replacement setup violated account boundaries")
	}
}

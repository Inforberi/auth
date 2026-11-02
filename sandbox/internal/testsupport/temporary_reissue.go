package testsupport

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func PendingLifecycleTemporary(t *testing.T, admin, api *http.Client, suffix string) (AdminAccount, string, string) {
	t.Helper()
	account := AdminAccount{Email: "retemporary-" + suffix + "@sandbox.example"}
	var issued struct{ UserID, Password string }
	Request(t, admin, "POST", "/api/v1/admin/users/temporary-password", map[string]string{"idempotencyKey": AdminCommand(t), "email": account.Email}, &issued, 201, "Origin", SandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Password == "" {
		t.Fatal("missing temporary account/secret")
	}
	var setup struct{ Token string }
	AssertNoLifecycleSession(t, Request(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": issued.Password}, &setup, 200, "Origin", SandboxURL))
	if setup.Token == "" {
		t.Fatal("missing pending setup proof")
	}
	return account, issued.Password, setup.Token
}

func CheckTemporaryReissue(t *testing.T, admin, api *http.Client, account AdminAccount, oldPassword, oldSetup string, command map[string]string) {
	t.Helper()
	before := ReadAdminUser(t, admin, account.ID)
	path := "/api/v1/admin/users/" + account.ID + "/temporary-password"
	var issued struct {
		UserID, Password string
		Reused           bool
		ExpiresAt        time.Time
	}
	AssertNoLifecycleSession(t, Request(t, admin, "POST", path, command, &issued, 200, "Origin", SandboxURL))
	if issued.UserID != account.ID || issued.Reused || issued.Password == "" || issued.Password == oldPassword || !issued.ExpiresAt.After(time.Now()) {
		t.Fatal("invalid replacement temporary credential")
	}
	var replay map[string]json.RawMessage
	AssertNoLifecycleSession(t, Request(t, admin, "POST", path, command, &replay, 200, "Origin", SandboxURL))
	var owner string
	var expiry time.Time
	if json.Unmarshal(replay["userId"], &owner) != nil || owner != account.ID || string(replay["reused"]) != "true" || replay["password"] != nil || json.Unmarshal(replay["expiresAt"], &expiry) != nil || !expiry.Equal(issued.ExpiresAt) {
		t.Fatal("reissue replay exposed password or changed owner/expiry")
	}
	card := ReadAdminUser(t, admin, account.ID)
	if card.Status != "pending" || card.AuthVersion <= before.AuthVersion || card.EmailVerified || !card.TemporaryPasswordRequired {
		t.Fatal("reissue did not replace pending account authority")
	}
	ExpectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": oldPassword}, 400, "invalid_temporary_password")
	complete := map[string]string{"token": oldSetup, "password": AdminTestPassword, "confirmPassword": AdminTestPassword}
	ExpectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	var setup struct{ Token string }
	AssertNoLifecycleSession(t, Request(t, api, "POST", "/api/v1/auth/temporary-password/login", map[string]string{"email": account.Email, "password": issued.Password}, &setup, 200, "Origin", SandboxURL))
	if setup.Token == "" || setup.Token == oldSetup {
		t.Fatal("replacement password did not yield a new setup proof")
	}
	complete["token"] = setup.Token
	AssertNoLifecycleSession(t, Request(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, nil, 200, "Origin", SandboxURL))
	ExpectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	card = ReadAdminUser(t, admin, account.ID)
	if card.Status != "active" || card.EmailVerified || card.TemporaryPasswordRequired || !card.PasswordConfigured || len(card.Roles) != 0 {
		t.Fatal("replacement setup violated account boundaries")
	}
}

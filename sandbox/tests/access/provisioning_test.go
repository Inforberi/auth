package sandbox_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func activateAdminTemporary(t *testing.T, admin, api *http.Client, suffix string) testsupport.AdminAccount {
	t.Helper()
	account := testsupport.AdminAccount{Email: "temporary-" + suffix + "@sandbox.example"}
	input := map[string]string{"idempotencyKey": testsupport.AdminCommand(t), "email": account.Email}
	var issued struct {
		UserID    string    `json:"userId"`
		Password  string    `json:"password"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	h := testsupport.Request(t, admin, "POST", "/api/v1/admin/users/temporary-password", input, &issued, 201, "Origin", testsupport.SandboxURL)
	account.ID = issued.UserID
	if account.ID == "" || issued.Password == "" || !issued.ExpiresAt.After(time.Now()) || h.Get("Cache-Control") != "no-store" || h.Get("Set-Cookie") != "" {
		t.Fatal("invalid one-time temporary-password response")
	}
	var replay map[string]json.RawMessage
	testsupport.Request(t, admin, "POST", "/api/v1/admin/users/temporary-password", input, &replay, 200, "Origin", testsupport.SandboxURL)
	var owner string
	if json.Unmarshal(replay["userId"], &owner) != nil || owner != account.ID || string(replay["reused"]) != "true" || replay["password"] != nil || replay["expiresAt"] != nil {
		t.Fatal("temporary replay exposed secret/expiry or changed owner")
	}
	credentials := map[string]string{"email": account.Email, "password": issued.Password}
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/login/email", credentials, 400, "invalid_credentials")
	var setup struct{ Token, Status string }
	h = testsupport.Request(t, api, "POST", "/api/v1/auth/temporary-password/login", credentials, &setup, 200, "Origin", testsupport.SandboxURL)
	if setup.Token == "" || setup.Status != "password_change_required" || h.Get("Set-Cookie") != "" {
		t.Fatal("temporary login created unrestricted access")
	}
	testsupport.Request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401)
	var samePassword struct {
		Code string `json:"code"`
	}
	testsupport.Request(t, api, "POST", "/api/v1/auth/temporary-password/complete", map[string]string{"token": setup.Token, "password": issued.Password, "confirmPassword": issued.Password}, &samePassword, 400, "Origin", testsupport.SandboxURL)
	// Random temporary secrets need not meet the composition policy for chosen passwords.
	if samePassword.Code != "same_password" && samePassword.Code != "password_policy" {
		t.Fatal("temporary password was not rejected as a permanent password")
	}
	complete := map[string]string{"token": setup.Token, "password": testsupport.AdminTestPassword, "confirmPassword": testsupport.AdminTestPassword}
	h = testsupport.Request(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, nil, 200, "Origin", testsupport.SandboxURL)
	if h.Get("Set-Cookie") != "" || h.Get("Cache-Control") != "no-store" {
		t.Fatal("password setup created a session or cacheable response")
	}
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/temporary-password/complete", complete, 400, "invalid_temporary_password")
	card := testsupport.ReadAdminUser(t, admin, account.ID)
	if card.Status != "active" || card.EmailVerified || !card.PasswordConfigured || card.TemporaryPasswordRequired || len(card.Roles) != 0 {
		t.Fatal("temporary setup verified email, granted roles or left a pending account")
	}
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/login/email", credentials, 400, "invalid_credentials")
	client := testsupport.LoginAdminTestUser(t, account)
	var access struct {
		Permissions []string `json:"permissions"`
	}
	testsupport.Request(t, client, "GET", "/api/v1/auth/access", nil, &access, 200)
	if len(access.Permissions) != 0 {
		t.Fatal("temporary setup implicitly granted permissions")
	}
	return account
}

func checkAdminDirectory(t *testing.T, admin *http.Client, accounts ...testsupport.AdminAccount) {
	t.Helper()
	for _, account := range accounts {
		var page struct {
			Users []testsupport.AdminUserCard `json:"users"`
		}
		testsupport.Request(t, admin, "GET", "/api/v1/admin/users?limit=1&status=active&email="+url.QueryEscape(account.Email), nil, &page, 200)
		if len(page.Users) != 1 || page.Users[0].ID != account.ID {
			t.Fatal("exact email/status filter returned the wrong user")
		}
	}
	var first struct {
		Users      []testsupport.AdminUserCard `json:"users"`
		NextCursor string                      `json:"nextCursor"`
	}
	testsupport.Request(t, admin, "GET", "/api/v1/admin/users?limit=1", nil, &first, 200)
	var second struct {
		Users []testsupport.AdminUserCard `json:"users"`
	}
	if len(first.Users) != 1 || first.NextCursor == "" {
		t.Fatal("missing bounded directory cursor")
	}
	testsupport.Request(t, admin, "GET", "/api/v1/admin/users?limit=1&before="+url.QueryEscape(first.NextCursor), nil, &second, 200)
	if len(second.Users) != 1 || first.Users[0].ID == second.Users[0].ID {
		t.Fatal("directory cursor repeated a user")
	}
}

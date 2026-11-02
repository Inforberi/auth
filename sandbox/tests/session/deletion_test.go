package sandbox_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func checkLifecycleDeletion(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, accounts ...testsupport.AdminAccount) {
	t.Helper()
	var role testsupport.AdminRole
	definition := map[string]any{"key": "sandbox_delete_" + strings.ReplaceAll(testsupport.AdminCommand(t), "-", ""), "name": "Deletion acceptance", "permissions": []string{"accounts.users.read"}}
	testsupport.Request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", testsupport.SandboxURL)
	for _, account := range accounts {
		checkDeletedCredentials(t, admin, api, consumer, role, account)
	}
}

func checkDeletedCredentials(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, role testsupport.AdminRole, account testsupport.AdminAccount) {
	t.Helper()
	path := "/api/v1/admin/users/" + account.ID
	card := testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "POST", path+"/roles/"+role.ID, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	// A failed assertion must not leave this run's ordinary user with management access.
	t.Cleanup(func() {
		current := testsupport.ReadAdminUser(t, admin, account.ID)
		// Deletion retains historical role links, but the tombstone cannot authorize them.
		if current.DeletedAt != nil {
			return
		}
		for _, assigned := range current.Roles {
			if assigned.ID == role.ID {
				testsupport.Request(t, admin, "DELETE", path+"/roles/"+role.ID, testsupport.AssignmentBody(role, current), nil, 200, "Origin", testsupport.SandboxURL)
			}
		}
	})
	user := testsupport.LoginAdminTestUser(t, account)
	u, err := url.Parse(testsupport.SandboxURL)
	if err != nil {
		t.Fatal(err)
	}
	var oldCookie string
	for _, cookie := range user.Jar.Cookies(u) {
		if cookie.Name == "__Host-session" {
			oldCookie = cookie.Name + "=" + cookie.Value
		}
	}
	if oldCookie == "" {
		t.Fatal("missing pre-deletion cookie")
	}
	access := testsupport.AdminReadToken(t, user)
	var native testsupport.TokenResponse
	input := map[string]any{"email": account.Email, "password": testsupport.AdminTestPassword, "audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}
	testsupport.AssertNoLifecycleSession(t, testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", input, &native, 200))
	if native.AccessToken == "" || native.RefreshToken == "" {
		t.Fatal("missing native credentials before deletion")
	}
	testsupport.Consume(t, consumer, access.AccessToken, "accounts.users.read", 204)
	testsupport.Consume(t, consumer, native.AccessToken, "accounts.users.read", 204)
	card = testsupport.ReadAdminUser(t, admin, account.ID)
	command := map[string]any{"expectedAuthVersion": card.AuthVersion}
	var deleted struct{ AuthVersion int64 }
	testsupport.AssertNoLifecycleSession(t, testsupport.Request(t, admin, "DELETE", path, command, &deleted, 200, "Origin", testsupport.SandboxURL))
	if deleted.AuthVersion <= card.AuthVersion {
		t.Fatal("deletion did not advance auth version")
	}
	tombstone := testsupport.ReadAdminUser(t, admin, account.ID)
	if tombstone.DeletedAt == nil || tombstone.Status != "blocked" || tombstone.PasswordConfigured || tombstone.AuthVersion != deleted.AuthVersion {
		t.Fatal("deletion did not retain a blocked, credential-free tombstone")
	}
	testsupport.AssertUnexpired(t, access, native)
	testsupport.Request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Cookie", oldCookie)
	testsupport.Consume(t, consumer, access.AccessToken, "accounts.users.read", 401)
	testsupport.Consume(t, consumer, native.AccessToken, "accounts.users.read", 401)
	testsupport.Request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": native.RefreshToken}, nil, 401)
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": testsupport.AdminTestPassword}, 400, "invalid_credentials")
	testsupport.Request(t, api, "POST", "/api/v1/auth/native/password/login", input, nil, 401)
	testsupport.ExpectAdminError(t, admin, "DELETE", path, command, 409, "account_conflict")
	var replay struct{ AuthVersion int64 }
	testsupport.Request(t, admin, "DELETE", path, map[string]any{"expectedAuthVersion": deleted.AuthVersion}, &replay, 200, "Origin", testsupport.SandboxURL)
	if replay.AuthVersion != deleted.AuthVersion {
		t.Fatal("idempotent deletion changed the tombstone version")
	}
	testsupport.ExpectAdminError(t, admin, "POST", path+"/status", map[string]any{"status": "active", "expectedAuthVersion": deleted.AuthVersion}, 409, "account_deleted")
	t.Logf("deleted only this run's synthetic user: %s", account.ID)
}

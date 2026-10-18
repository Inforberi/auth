package sandbox_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkLifecycleDeletion(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, accounts ...adminAccount) {
	t.Helper()
	var role adminRole
	definition := map[string]any{"key": "sandbox_delete_" + strings.ReplaceAll(adminCommand(t), "-", ""), "name": "Deletion acceptance", "permissions": []string{"accounts.users.read"}}
	request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", sandboxURL)
	for _, account := range accounts {
		checkDeletedCredentials(t, admin, api, consumer, role, account)
	}
}

func checkDeletedCredentials(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, role adminRole, account adminAccount) {
	t.Helper()
	path := "/api/v1/admin/users/" + account.ID
	card := readAdminUser(t, admin, account.ID)
	request(t, admin, "POST", path+"/roles/"+role.ID, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	// A failed assertion must not leave this run's ordinary user with management access.
	t.Cleanup(func() {
		current := readAdminUser(t, admin, account.ID)
		// Deletion retains historical role links, but the tombstone cannot authorize them.
		if current.DeletedAt != nil {
			return
		}
		for _, assigned := range current.Roles {
			if assigned.ID == role.ID {
				request(t, admin, "DELETE", path+"/roles/"+role.ID, assignmentBody(role, current), nil, 200, "Origin", sandboxURL)
			}
		}
	})
	user := loginAdminTestUser(t, account)
	u, err := url.Parse(sandboxURL)
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
	access := adminReadToken(t, user)
	var native tokenResponse
	input := map[string]any{"email": account.Email, "password": adminTestPassword, "audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}
	assertNoLifecycleSession(t, request(t, api, "POST", "/api/v1/auth/native/password/login", input, &native, 200))
	if native.AccessToken == "" || native.RefreshToken == "" {
		t.Fatal("missing native credentials before deletion")
	}
	consume(t, consumer, access.AccessToken, "accounts.users.read", 204)
	consume(t, consumer, native.AccessToken, "accounts.users.read", 204)
	card = readAdminUser(t, admin, account.ID)
	command := map[string]any{"expectedAuthVersion": card.AuthVersion}
	var deleted struct{ AuthVersion int64 }
	assertNoLifecycleSession(t, request(t, admin, "DELETE", path, command, &deleted, 200, "Origin", sandboxURL))
	if deleted.AuthVersion <= card.AuthVersion {
		t.Fatal("deletion did not advance auth version")
	}
	tombstone := readAdminUser(t, admin, account.ID)
	if tombstone.DeletedAt == nil || tombstone.Status != "blocked" || tombstone.PasswordConfigured || tombstone.AuthVersion != deleted.AuthVersion {
		t.Fatal("deletion did not retain a blocked, credential-free tombstone")
	}
	assertUnexpired(t, access, native)
	request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Cookie", oldCookie)
	consume(t, consumer, access.AccessToken, "accounts.users.read", 401)
	consume(t, consumer, native.AccessToken, "accounts.users.read", 401)
	request(t, api, "POST", "/api/v1/auth/token/refresh", map[string]string{"refreshToken": native.RefreshToken}, nil, 401)
	expectAdminError(t, api, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": adminTestPassword}, 400, "invalid_credentials")
	request(t, api, "POST", "/api/v1/auth/native/password/login", input, nil, 401)
	expectAdminError(t, admin, "DELETE", path, command, 409, "account_conflict")
	var replay struct{ AuthVersion int64 }
	request(t, admin, "DELETE", path, map[string]any{"expectedAuthVersion": deleted.AuthVersion}, &replay, 200, "Origin", sandboxURL)
	if replay.AuthVersion != deleted.AuthVersion {
		t.Fatal("idempotent deletion changed the tombstone version")
	}
	expectAdminError(t, admin, "POST", path+"/status", map[string]any{"status": "active", "expectedAuthVersion": deleted.AuthVersion}, 409, "account_deleted")
	t.Logf("deleted only this run's synthetic user: %s", account.ID)
}

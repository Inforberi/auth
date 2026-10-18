package sandbox_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func checkLastAdministrator(t *testing.T, admin *http.Client) {
	t.Helper()
	var me struct {
		UserID string `json:"userId"`
	}
	request(t, admin, "GET", "/api/v1/auth/me", nil, &me, 200)
	card := readAdminUser(t, admin, me.UserID)
	var system adminRole
	for _, role := range card.Roles {
		if role.System {
			system = role
		}
	}
	if system.ID == "" {
		t.Fatal("missing system administrator role")
	}
	path := "/api/v1/admin/users/" + card.ID
	expectAdminError(t, admin, "POST", path+"/status", map[string]any{"status": "blocked", "expectedAuthVersion": card.AuthVersion}, 409, "last_administrator")
	expectAdminError(t, admin, "DELETE", path, map[string]any{"expectedAuthVersion": card.AuthVersion}, 409, "last_administrator")
	expectAdminError(t, admin, "DELETE", path+"/administrator", map[string]any{"expectedAuthVersion": card.AuthVersion, "expectedAccessVersion": card.AccessVersion, "expectedRoleVersion": system.Version}, 409, "last_administrator")
	after := readAdminUser(t, admin, card.ID)
	if after.Status != "active" || after.AuthVersion != card.AuthVersion || after.AccessVersion != card.AccessVersion {
		t.Fatal("last-administrator denial changed authority")
	}
}

func checkAdminAccess(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, account adminAccount, definition map[string]any) {
	t.Helper()
	user := loginAdminTestUser(t, account)
	request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 403)
	var role adminRole
	request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", sandboxURL)
	if role.ID == "" || role.Version != 1 || role.System {
		t.Fatal("invalid custom role")
	}
	t.Cleanup(func() {
		card := readAdminUser(t, admin, account.ID)
		for _, assigned := range card.Roles {
			if assigned.ID == role.ID {
				var current adminRole
				request(t, admin, "GET", "/api/v1/admin/roles/"+role.ID, nil, &current, 200)
				request(t, admin, "DELETE", "/api/v1/admin/users/"+account.ID+"/roles/"+role.ID, assignmentBody(current, card), nil, 200, "Origin", sandboxURL)
			}
		}
	})
	t.Logf("synthetic custom role retained for inspection: %s", role.ID)
	expectAdminError(t, admin, "POST", "/api/v1/admin/roles", definition, 409, "access_conflict")
	invalid := map[string]any{"key": role.Key + "_invalid", "name": "Invalid", "permissions": []string{"unregistered.permission"}}
	expectAdminError(t, admin, "POST", "/api/v1/admin/roles", invalid, 400, "invalid_permission")
	var me struct {
		UserID string `json:"userId"`
	}
	request(t, admin, "GET", "/api/v1/auth/me", nil, &me, 200)
	self := readAdminUser(t, admin, me.UserID)
	expectAdminError(t, admin, "POST", "/api/v1/admin/users/"+self.ID+"/roles/"+role.ID, assignmentBody(role, self), 403, "forbidden")

	card := readAdminUser(t, admin, account.ID)
	path := "/api/v1/admin/users/" + account.ID + "/roles/" + role.ID
	oldAssignment := assignmentBody(role, card)
	request(t, admin, "POST", path, oldAssignment, nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	expectAdminError(t, admin, "POST", path, oldAssignment, 409, "access_conflict")
	user = loginAdminTestUser(t, account)
	request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 200)
	request(t, user, "GET", "/api/v1/admin/roles", nil, nil, 403)
	token := adminReadToken(t, user)
	consume(t, consumer, token.AccessToken, "accounts.users.read", 204)
	card = readAdminUser(t, admin, account.ID)
	request(t, admin, "POST", path, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)

	t.Log("role expansion invalidates old snapshots; pure reduction does not require re-login")
	update := roleUpdate(role, []string{"accounts.users.read", "accounts.users.manage"})
	request(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, &role, 200, "Origin", sandboxURL)
	assertUnexpired(t, token)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	user = loginAdminTestUser(t, account)
	var access struct {
		Permissions []string `json:"permissions"`
	}
	request(t, user, "GET", "/api/v1/auth/access", nil, &access, 200)
	if !slices.Contains(access.Permissions, "accounts.users.manage") {
		t.Fatal("new login did not receive expanded role")
	}
	token = adminReadToken(t, user)
	request(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, roleUpdate(role, []string{"accounts.users.read"}), &role, 200, "Origin", sandboxURL)
	expectAdminError(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, 409, "access_conflict")
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	request(t, user, "GET", "/api/v1/auth/access", nil, &access, 200)
	if slices.Contains(access.Permissions, "accounts.users.manage") {
		t.Fatal("removed role permission survived")
	}
	consume(t, consumer, token.AccessToken, "accounts.users.read", 204)

	card = readAdminUser(t, admin, account.ID)
	request(t, admin, "DELETE", path, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 403)
	assertUnexpired(t, token)
	consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	card = readAdminUser(t, admin, account.ID)
	request(t, admin, "POST", path, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	user = loginAdminTestUser(t, account)
	token = adminReadToken(t, user)
	checkAdminBlocking(t, admin, api, consumer, account, user, token)

	// Leave only this run's new accounts and role, without any assigned administrative access.
	card = readAdminUser(t, admin, account.ID)
	request(t, admin, "DELETE", path, assignmentBody(role, card), nil, 200, "Origin", sandboxURL)
	if len(readAdminUser(t, admin, account.ID).Roles) != 0 {
		t.Fatal("test account retained administrative access")
	}
}

func checkAdminBlocking(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, account adminAccount, user *http.Client, token tokenResponse) {
	t.Helper()
	endpoint, err := url.Parse(sandboxURL)
	if err != nil {
		t.Fatal(err)
	}
	oldCookie := ""
	for _, cookie := range user.Jar.Cookies(endpoint) {
		if cookie.Name == "__Host-session" {
			oldCookie = cookie.Name + "=" + cookie.Value
		}
	}
	if oldCookie == "" {
		t.Fatal("missing pre-block credential")
	}
	path := "/api/v1/admin/users/" + account.ID + "/status"
	card := readAdminUser(t, admin, account.ID)
	blocked := map[string]any{"status": "blocked", "expectedAuthVersion": card.AuthVersion}
	request(t, admin, "POST", path, blocked, nil, 200, "Origin", sandboxURL)
	request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	assertUnexpired(t, token)
	consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	expectAdminError(t, api, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": adminTestPassword}, 400, "invalid_credentials")
	expectAdminError(t, admin, "POST", path, map[string]any{"status": "active", "expectedAuthVersion": card.AuthVersion}, 409, "account_conflict")
	card = readAdminUser(t, admin, account.ID)
	if card.Status != "blocked" {
		t.Fatal("blocked account status was not stored")
	}
	request(t, admin, "POST", path, map[string]any{"status": "active", "expectedAuthVersion": card.AuthVersion}, nil, 200, "Origin", sandboxURL)
	// Re-send the original bytes, independently of any cookie clearing on earlier failures.
	request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Cookie", oldCookie)
	consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	fresh := loginAdminTestUser(t, account)
	consume(t, consumer, adminReadToken(t, fresh).AccessToken, "accounts.users.read", 204)
}

func assignmentBody(role adminRole, card adminUserCard) map[string]any {
	return map[string]any{"expectedRoleVersion": role.Version, "expectedAccessVersion": card.AccessVersion}
}

func roleUpdate(role adminRole, permissions []string) map[string]any {
	return map[string]any{"key": role.Key, "name": "Sandbox reader", "permissions": permissions, "expectedVersion": role.Version}
}

func adminReadToken(t *testing.T, client *http.Client) tokenResponse {
	t.Helper()
	var token tokenResponse
	request(t, client, "POST", "/api/v1/auth/token/exchange", map[string]any{"audience": "sandbox-strict", "scope": []string{"accounts.users.read"}}, &token, 200, "Origin", sandboxURL)
	if token.AccessToken == "" {
		t.Fatal("missing role-scoped access token")
	}
	return token
}

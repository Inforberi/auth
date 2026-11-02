package sandbox_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
	testsupport "github.com/Inforberi/financial-intelligence/sandbox/internal/testsupport"
)

func checkLastAdministrator(t *testing.T, admin *http.Client) {
	t.Helper()
	var me struct {
		UserID string `json:"userId"`
	}
	testsupport.Request(t, admin, "GET", "/api/v1/auth/me", nil, &me, 200)
	card := testsupport.ReadAdminUser(t, admin, me.UserID)
	var system testsupport.AdminRole
	for _, role := range card.Roles {
		if role.System {
			system = role
		}
	}
	if system.ID == "" {
		t.Fatal("missing system administrator role")
	}
	path := "/api/v1/admin/users/" + card.ID
	testsupport.ExpectAdminError(t, admin, "POST", path+"/status", map[string]any{"status": "blocked", "expectedAuthVersion": card.AuthVersion}, 409, "last_administrator")
	testsupport.ExpectAdminError(t, admin, "DELETE", path, map[string]any{"expectedAuthVersion": card.AuthVersion}, 409, "last_administrator")
	testsupport.ExpectAdminError(t, admin, "DELETE", path+"/administrator", map[string]any{"expectedAuthVersion": card.AuthVersion, "expectedAccessVersion": card.AccessVersion, "expectedRoleVersion": system.Version}, 409, "last_administrator")
	after := testsupport.ReadAdminUser(t, admin, card.ID)
	if after.Status != "active" || after.AuthVersion != card.AuthVersion || after.AccessVersion != card.AccessVersion {
		t.Fatal("last-administrator denial changed authority")
	}
}

func checkAdminAccess(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, account testsupport.AdminAccount, definition map[string]any) {
	t.Helper()
	user := testsupport.LoginAdminTestUser(t, account)
	testsupport.Request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 403)
	var role testsupport.AdminRole
	testsupport.Request(t, admin, "POST", "/api/v1/admin/roles", definition, &role, 201, "Origin", testsupport.SandboxURL)
	if role.ID == "" || role.Version != 1 || role.System {
		t.Fatal("invalid custom role")
	}
	t.Cleanup(func() {
		card := testsupport.ReadAdminUser(t, admin, account.ID)
		for _, assigned := range card.Roles {
			if assigned.ID == role.ID {
				var current testsupport.AdminRole
				testsupport.Request(t, admin, "GET", "/api/v1/admin/roles/"+role.ID, nil, &current, 200)
				testsupport.Request(t, admin, "DELETE", "/api/v1/admin/users/"+account.ID+"/roles/"+role.ID, testsupport.AssignmentBody(current, card), nil, 200, "Origin", testsupport.SandboxURL)
			}
		}
	})
	t.Logf("synthetic custom role retained for inspection: %s", role.ID)
	testsupport.ExpectAdminError(t, admin, "POST", "/api/v1/admin/roles", definition, 409, "access_conflict")
	invalid := map[string]any{"key": role.Key + "_invalid", "name": "Invalid", "permissions": []string{"unregistered.permission"}}
	testsupport.ExpectAdminError(t, admin, "POST", "/api/v1/admin/roles", invalid, 400, "invalid_permission")
	var me struct {
		UserID string `json:"userId"`
	}
	testsupport.Request(t, admin, "GET", "/api/v1/auth/me", nil, &me, 200)
	self := testsupport.ReadAdminUser(t, admin, me.UserID)
	testsupport.ExpectAdminError(t, admin, "POST", "/api/v1/admin/users/"+self.ID+"/roles/"+role.ID, testsupport.AssignmentBody(role, self), 403, "forbidden")

	card := testsupport.ReadAdminUser(t, admin, account.ID)
	path := "/api/v1/admin/users/" + account.ID + "/roles/" + role.ID
	oldAssignment := testsupport.AssignmentBody(role, card)
	testsupport.Request(t, admin, "POST", path, oldAssignment, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.ExpectAdminError(t, admin, "POST", path, oldAssignment, 409, "access_conflict")
	user = testsupport.LoginAdminTestUser(t, account)
	testsupport.Request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 200)
	testsupport.Request(t, user, "GET", "/api/v1/admin/roles", nil, nil, 403)
	token := testsupport.AdminReadToken(t, user)
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 204)
	card = testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "POST", path, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)

	t.Log("role expansion invalidates old snapshots; pure reduction does not require re-login")
	update := testsupport.RoleUpdate(role, []string{"accounts.users.read", "accounts.users.manage"})
	testsupport.Request(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, &role, 200, "Origin", testsupport.SandboxURL)
	testsupport.AssertUnexpired(t, token)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	user = testsupport.LoginAdminTestUser(t, account)
	var access struct {
		Permissions []string `json:"permissions"`
	}
	testsupport.Request(t, user, "GET", "/api/v1/auth/access", nil, &access, 200)
	if !slices.Contains(access.Permissions, "accounts.users.manage") {
		t.Fatal("new login did not receive expanded role")
	}
	token = testsupport.AdminReadToken(t, user)
	testsupport.Request(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, testsupport.RoleUpdate(role, []string{"accounts.users.read"}), &role, 200, "Origin", testsupport.SandboxURL)
	testsupport.ExpectAdminError(t, admin, "POST", "/api/v1/admin/roles/"+role.ID, update, 409, "access_conflict")
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	testsupport.Request(t, user, "GET", "/api/v1/auth/access", nil, &access, 200)
	if slices.Contains(access.Permissions, "accounts.users.manage") {
		t.Fatal("removed role permission survived")
	}
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 204)

	card = testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "DELETE", path, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 200)
	testsupport.Request(t, user, "GET", "/api/v1/admin/users?limit=1", nil, nil, 403)
	testsupport.AssertUnexpired(t, token)
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	card = testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "POST", path, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	user = testsupport.LoginAdminTestUser(t, account)
	token = testsupport.AdminReadToken(t, user)
	checkAdminBlocking(t, admin, api, consumer, account, user, token)

	// Leave only this run's new accounts and role, without any assigned administrative access.
	card = testsupport.ReadAdminUser(t, admin, account.ID)
	testsupport.Request(t, admin, "DELETE", path, testsupport.AssignmentBody(role, card), nil, 200, "Origin", testsupport.SandboxURL)
	if len(testsupport.ReadAdminUser(t, admin, account.ID).Roles) != 0 {
		t.Fatal("test account retained administrative access")
	}
}

func checkAdminBlocking(t *testing.T, admin, api *http.Client, consumer *authjwt.Consumer, account testsupport.AdminAccount, user *http.Client, token testsupport.TokenResponse) {
	t.Helper()
	endpoint, err := url.Parse(testsupport.SandboxURL)
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
	card := testsupport.ReadAdminUser(t, admin, account.ID)
	blocked := map[string]any{"status": "blocked", "expectedAuthVersion": card.AuthVersion}
	testsupport.Request(t, admin, "POST", path, blocked, nil, 200, "Origin", testsupport.SandboxURL)
	testsupport.Request(t, user, "GET", "/api/v1/auth/me", nil, nil, 401)
	testsupport.AssertUnexpired(t, token)
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	testsupport.ExpectAdminError(t, api, "POST", "/api/v1/auth/login/email", map[string]string{"email": account.Email, "password": testsupport.AdminTestPassword}, 400, "invalid_credentials")
	testsupport.ExpectAdminError(t, admin, "POST", path, map[string]any{"status": "active", "expectedAuthVersion": card.AuthVersion}, 409, "account_conflict")
	card = testsupport.ReadAdminUser(t, admin, account.ID)
	if card.Status != "blocked" {
		t.Fatal("blocked account status was not stored")
	}
	testsupport.Request(t, admin, "POST", path, map[string]any{"status": "active", "expectedAuthVersion": card.AuthVersion}, nil, 200, "Origin", testsupport.SandboxURL)
	// Re-send the original bytes, independently of any cookie clearing on earlier failures.
	testsupport.Request(t, api, "GET", "/api/v1/auth/me", nil, nil, 401, "Cookie", oldCookie)
	testsupport.Consume(t, consumer, token.AccessToken, "accounts.users.read", 401)
	fresh := testsupport.LoginAdminTestUser(t, account)
	testsupport.Consume(t, consumer, testsupport.AdminReadToken(t, fresh).AccessToken, "accounts.users.read", 204)
}

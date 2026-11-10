package projects_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkProjectAccessIsolation(t *testing.T, ctx context.Context, f projectIsolationHTTP, webs [2]isolationHTTP) {
	t.Helper()
	const roles = "/api/v1/admin/roles"
	owners := [2]string{isolationAdminLogin(t, ctx, webs[0], httpOwnerEmail), isolationAdminLogin(t, ctx, webs[1], httpOwnerEmail)}
	manager := isolationAdminLogin(t, ctx, webs[0], httpManagerEmail)
	var managerAuthVersion accountdomain.AuthVersion
	var managerAccessVersion, systemRoleVersion int64
	require.NoError(t, f.databases[0].QueryRow(ctx, `SELECT auth_version,access_version FROM auth.users WHERE id=$1`, httpManagerID).Scan(&managerAuthVersion, &managerAccessVersion))
	require.NoError(t, f.databases[0].QueryRow(ctx, `SELECT version FROM auth.roles WHERE key='super_admin'`).Scan(&systemRoleVersion))
	selfPromotion := accesshttp.AdministratorRequest{ExpectedAuthVersion: managerAuthVersion, ExpectedAccessVersion: managerAccessVersion, ExpectedRoleVersion: systemRoleVersion}
	promotionResponse := webs[0].call(t, ctx, "POST", "/api/v1/admin/users/"+httpManagerID+"/administrator", webs[0].origin, manager, selfPromotion)
	require.Equal(t, 403, promotionResponse.status, "%s", promotionResponse.body)
	var managerPromoted bool
	require.NoError(t, f.databases[0].QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.key='super_admin')`, httpManagerID).Scan(&managerPromoted))
	require.False(t, managerPromoted, "a non-system project manager cannot promote itself")
	create := accesshttp.CreateRoleRequest{Key: "http_cross_reader", Name: "Reader", Permissions: []accessdomain.PermissionKey{"reports.read"}}
	var local [2]accesshttp.RoleResponse
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", roles, owners[1-i], nil, 401, nil)
		isolationCommand(t, ctx, web, "POST", roles, owners[1-i], create, 401, nil)
		isolationCommand(t, ctx, web, "POST", roles, owners[i], create, 201, &local[i])
	}
	require.NotEqual(t, local[0].ID, local[1].ID)
	for i, web := range webs {
		isolationCommand(t, ctx, web, "GET", roles+"/"+string(local[1-i].ID), owners[i], nil, 404, nil)
		assignment := accesshttp.AssignmentRequest{ExpectedRoleVersion: 1, ExpectedAccessVersion: 1}
		isolationCommand(t, ctx, web, "POST", "/api/v1/admin/users/"+httpIsolationUser+"/roles/"+string(local[1-i].ID), owners[i], assignment, 404, nil)
		self := accesshttp.AdministratorRequest{ExpectedAuthVersion: 1, ExpectedAccessVersion: 1, ExpectedRoleVersion: 1}
		response := web.call(t, ctx, "DELETE", "/api/v1/admin/users/"+httpOwnerID+"/administrator", web.origin, owners[i], self)
		require.Equal(t, 409, response.status, "%s", response.body)
		require.Contains(t, string(response.body), `"code":"last_administrator"`, "the owner of the other DB cannot satisfy the last-admin guard")
	}
	_, err := f.databases[0].Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, httpForeignID)
	require.NoError(t, err)
	isolationCommand(t, ctx, webs[1], "POST", "/api/v1/admin/users/"+httpForeignID+"/roles/"+string(local[1].ID), owners[1], accesshttp.AssignmentRequest{ExpectedRoleVersion: 1, ExpectedAccessVersion: 1}, 409, nil)
	denied := accesshttp.CreateRoleRequest{Key: "http_forbidden", Name: "No delegation", Permissions: []accessdomain.PermissionKey{"reports.write"}}
	isolationCommand(t, ctx, webs[0], "POST", roles, manager, denied, 403, nil)
	allowed := accesshttp.CreateRoleRequest{Key: "http_manager_reader", Name: "Delegated reader", Permissions: create.Permissions}
	isolationCommand(t, ctx, webs[0], "POST", roles, manager, allowed, 201, nil)
	// Age only the private mutation proof; the session must remain readable.
	_, err = f.databases[0].Exec(ctx, `UPDATE auth.sessions SET password_verified_at=clock_timestamp()-interval '10 minutes' WHERE token_hash=$1`, tokengenerate.New().Hash(isolationRawCookie(manager)))
	require.NoError(t, err)
	isolationCommand(t, ctx, webs[0], "GET", roles, manager, nil, 200, nil)
	allowed.Key = "http_stale_reader"
	stale := webs[0].call(t, ctx, "POST", roles, webs[0].origin, manager, allowed)
	require.Equal(t, 403, stale.status, "%s", stale.body)
	require.Contains(t, string(stale.body), `"code":"fresh_auth_required"`)
	login := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	var targetCookies [2]string
	for i, web := range webs {
		response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", login)
		require.Equal(t, 200, response.status)
		targetCookies[i] = response.cookie(t, "__Host-session")
	}
	assignmentPath := "/api/v1/admin/users/" + httpIsolationUser + "/roles/" + string(local[0].ID)
	grant := accesshttp.AssignmentRequest{ExpectedRoleVersion: 1, ExpectedAccessVersion: 1}
	var assigned accesshttp.AssignmentResponse
	isolationCommand(t, ctx, webs[0], "POST", assignmentPath, owners[0], grant, 200, &assigned)
	require.EqualValues(t, 2, assigned.AccessVersion)
	isolationCommand(t, ctx, webs[0], "POST", assignmentPath, owners[0], grant, 409, nil)
	isolationCommand(t, ctx, webs[0], "GET", "/api/v1/auth/access", targetCookies[0], nil, 401, nil)
	isolationCommand(t, ctx, webs[1], "GET", "/api/v1/auth/access", targetCookies[1], nil, 200, nil)
	readAccess := func(i int) accesshttp.AccessResponse {
		t.Helper()
		var result accesshttp.AccessResponse
		isolationCommand(t, ctx, webs[i], "GET", "/api/v1/admin/users/"+httpIsolationUser+"/access", owners[i], nil, 200, &result)
		return result
	}
	a, b := readAccess(0), readAccess(1)
	require.Contains(t, a.Permissions, accessdomain.PermissionKey("reports.read"))
	require.Empty(t, b.Permissions)
	require.EqualValues(t, 1, b.Version)
	update := accesshttp.UpdateRoleRequest{Key: create.Key, Name: "Renamed in A", Permissions: create.Permissions, ExpectedVersion: 1}
	isolationCommand(t, ctx, webs[0], "POST", roles+"/"+string(local[0].ID), owners[0], update, 200, &local[0])
	require.EqualValues(t, 2, local[0].Version)
	update.ExpectedVersion = local[0].Version
	isolationCommand(t, ctx, webs[1], "POST", roles+"/"+string(local[1].ID), owners[1], update, 409, nil)
	update.ExpectedVersion = 1
	update.Name = "Renamed independently in B"
	isolationCommand(t, ctx, webs[1], "POST", roles+"/"+string(local[1].ID), owners[1], update, 200, &local[1])
	grant.ExpectedRoleVersion, grant.ExpectedAccessVersion = 2, 2
	isolationCommand(t, ctx, webs[0], "DELETE", assignmentPath, owners[0], grant, 200, nil)
	require.Empty(t, readAccess(0).Permissions)
	require.Empty(t, readAccess(1).Permissions)
	require.EqualValues(t, 1, readAccess(1).Version)
	response := webs[1].call(t, ctx, "GET", roles+"/"+string(local[1].ID), webs[1].origin, owners[1], nil)
	var final accesshttp.RoleResponse
	require.Equal(t, 200, response.status)
	require.NoError(t, json.Unmarshal(response.body, &final))
	require.Equal(t, "Renamed independently in B", final.Name)
}

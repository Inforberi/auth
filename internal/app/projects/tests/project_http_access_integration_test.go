package projects_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	accesshttp "github.com/Inforberi/financial-intelligence/internal/access/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (f projectAccountFixture) httpAccess(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken string) {
	t.Helper()
	const target = "f8700000-0000-4000-8000-000000000001"
	const roleKey = "project_http_reader"
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1);
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 VALUES($2,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'access-fixture','192.0.2.87')`, target, tokens.Hash(raw))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.access_audit WHERE role_id IN(SELECT id FROM auth.roles WHERE key=$2);
 DELETE FROM auth.sessions WHERE user_id=$1;
 DELETE FROM auth.user_roles WHERE user_id=$1;
 DELETE FROM auth.users WHERE id=$1;
 DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key=$2);
 DELETE FROM auth.roles WHERE key=$2`, target, roleKey)
		require.NoError(t, err)
	})
	read := func(path, cookie string, expected int, result any) {
		t.Helper()
		status, cookies, body := web("GET", path, origin, cookie, "")
		require.Equal(t, expected, status, "%s: %s", path, body)
		require.Empty(t, cookies)
		if result != nil {
			require.NoError(t, json.Unmarshal(body, result))
		}
	}
	const roles = "/api/v1/admin/roles"
	read(roles, "", 401, nil)
	read(roles, raw, 403, nil)
	read("/api/v1/admin/permissions", actorToken, 200, nil)
	read(roles+"?limit=1", actorToken, 200, nil)
	create := accesshttp.CreateRoleRequest{Key: roleKey, Name: "Project reader", Permissions: []accessdomain.PermissionKey{accesssettings.UsersRead}}
	web.command(t, roles, "https://foreign.example.test", actorToken, create, 403, nil)
	web.command(t, roles, origin, raw, create, 403, nil)
	var role accesshttp.RoleResponse
	web.command(t, roles, origin, actorToken, create, 201, &role)
	require.False(t, role.System)
	require.EqualValues(t, 1, role.Version)
	read(roles+"/"+string(role.ID), actorToken, 200, nil)
	web.command(t, roles, origin, actorToken, create, 409, nil)
	invalid := create
	invalid.Permissions = []accessdomain.PermissionKey{"undeclared.read"}
	web.command(t, roles, origin, actorToken, invalid, 400, nil)
	invalid.Permissions = []accessdomain.PermissionKey{"reports.read"}
	web.command(t, roles, origin, actorToken, invalid, 403, nil)
	web.command(t, "/api/v1/admin/users/f8300000-0000-4000-8000-000000000001/roles/"+string(role.ID), origin, actorToken, accesshttp.AssignmentRequest{ExpectedRoleVersion: 1, ExpectedAccessVersion: 1}, 403, nil)
	assignmentPath := "/api/v1/admin/users/" + target + "/roles/" + string(role.ID)
	assignment := accesshttp.AssignmentRequest{ExpectedRoleVersion: 1, ExpectedAccessVersion: 1}
	var assigned accesshttp.AssignmentResponse
	web.command(t, assignmentPath, origin, actorToken, assignment, 200, &assigned)
	require.EqualValues(t, 2, assigned.AccessVersion)
	read("/api/v1/auth/access", raw, 401, nil)
	web.command(t, assignmentPath, origin, actorToken, assignment, 409, nil)
	var access accesshttp.AccessResponse
	read("/api/v1/admin/users/"+target+"/access", actorToken, 200, &access)
	require.EqualValues(t, 2, access.Version)
	require.Contains(t, access.Permissions, accesssettings.UsersRead)
	fresh, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 SELECT $2,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'access-fixture','192.0.2.87' FROM auth.users WHERE id=$1`, target, tokens.Hash(fresh))
	require.NoError(t, err)
	read("/api/v1/auth/access", fresh, 200, &access)
	require.Contains(t, access.Permissions, accesssettings.UsersRead)
	update := accesshttp.UpdateRoleRequest{Key: roleKey, Name: "Project reader and moderator", Permissions: []accessdomain.PermissionKey{accesssettings.UsersRead, accesssettings.UsersStatusManage}, ExpectedVersion: 1}
	web.command(t, roles+"/"+string(role.ID), origin, actorToken, update, 200, &role)
	require.EqualValues(t, 2, role.Version)
	read("/api/v1/auth/access", fresh, 401, nil)
	web.command(t, roles+"/"+string(role.ID), origin, actorToken, update, 409, nil)
	assignment.ExpectedRoleVersion, assignment.ExpectedAccessVersion = 2, 2
	web.commandMethod(t, "DELETE", assignmentPath, origin, actorToken, assignment, 200, &assigned)
	require.EqualValues(t, 3, assigned.AccessVersion)
	read("/api/v1/admin/users/"+target+"/access", actorToken, 200, &access)
	require.Empty(t, access.RoleIDs)
	require.Empty(t, access.Permissions)
	administrator := accesshttp.AdministratorRequest{ExpectedAuthVersion: 2, ExpectedAccessVersion: 3, ExpectedRoleVersion: 1}
	adminPath := "/api/v1/admin/users/" + target + "/administrator"
	web.command(t, adminPath, origin, actorToken, administrator, 403, nil)
	web.commandMethod(t, "DELETE", adminPath, origin, actorToken, administrator, 403, nil)
}

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
)

func checkProjectLifecycleIsolation(t *testing.T, ctx context.Context, f projectIsolationHTTP, webs [2]isolationHTTP) {
	t.Helper()
	const path = "/api/v1/admin/users/" + httpIsolationUser
	const me = "/api/v1/auth/me"
	owners := [2]string{isolationAdminLogin(t, ctx, webs[0], httpOwnerEmail), isolationAdminLogin(t, ctx, webs[1], httpOwnerEmail)}
	a, b := isolationSessionLogin(t, ctx, webs[0]), isolationSessionLogin(t, ctx, webs[1])
	var before accountdomain.AuthVersion
	require.NoError(t, f.databases[0].QueryRow(ctx, `SELECT auth_version FROM auth.users WHERE id=$1`, httpIsolationUser).Scan(&before))
	block := accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusBlocked, ExpectedAuthVersion: before}
	for i, web := range webs {
		isolationCommand(t, ctx, web, "POST", path+"/status", owners[1-i], block, 401, nil)
		isolationCommand(t, ctx, web, "DELETE", path, owners[1-i], accounthttp.DeleteUserRequest{ExpectedAuthVersion: before}, 401, nil)
	}
	var blocked accounthttp.UserLifecycleResponse
	isolationCommand(t, ctx, webs[0], "POST", path+"/status", owners[0], block, 200, &blocked)
	require.Equal(t, before+1, blocked.AuthVersion)
	isolationCommand(t, ctx, webs[0], "GET", me, a, nil, 401, nil)
	isolationCommand(t, ctx, webs[1], "GET", me, b, nil, 200, nil)
	login := map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword}
	isolationCommand(t, ctx, webs[0], "POST", "/api/v1/auth/login/email", "", login, 400, nil)
	isolationCommand(t, ctx, webs[0], "POST", path+"/status", owners[0], block, 409, nil)
	var active accounthttp.UserLifecycleResponse
	isolationCommand(t, ctx, webs[0], "POST", path+"/status", owners[0], accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusActive, ExpectedAuthVersion: blocked.AuthVersion}, 200, &active)
	require.Equal(t, blocked.AuthVersion+1, active.AuthVersion)
	isolationCommand(t, ctx, webs[0], "GET", me, a, nil, 401, nil)
	a = isolationSessionLogin(t, ctx, webs[0])
	var deleted accounthttp.UserLifecycleResponse
	request := accounthttp.DeleteUserRequest{ExpectedAuthVersion: active.AuthVersion}
	isolationCommand(t, ctx, webs[0], "DELETE", path, owners[0], request, 200, &deleted)
	require.Equal(t, active.AuthVersion+1, deleted.AuthVersion)
	isolationCommand(t, ctx, webs[0], "GET", me, a, nil, 401, nil)
	isolationCommand(t, ctx, webs[0], "POST", "/api/v1/auth/login/email", "", login, 400, nil)
	isolationCommand(t, ctx, webs[0], "DELETE", path, owners[0], request, 409, nil)
	isolationCommand(t, ctx, webs[0], "DELETE", path, owners[0], accounthttp.DeleteUserRequest{ExpectedAuthVersion: deleted.AuthVersion}, 200, nil)
	isolationCommand(t, ctx, webs[1], "GET", me, b, nil, 200, nil)
	b = isolationSessionLogin(t, ctx, webs[1])
	isolationCommand(t, ctx, webs[1], "GET", me, b, nil, 200, nil)
	var unchanged bool
	require.NoError(t, f.databases[1].QueryRow(ctx, `SELECT u.status='active' AND u.deleted_at IS NULL AND u.auth_version=1
 AND EXISTS(SELECT 1 FROM auth.password_credentials p WHERE p.user_id=u.id)
 AND NOT EXISTS(SELECT 1 FROM auth.account_status_audit a WHERE a.user_id=u.id)
 AND NOT EXISTS(SELECT 1 FROM auth.account_deletion_audit a WHERE a.user_id=u.id)
 FROM auth.users u WHERE u.id=$1`, httpIsolationUser).Scan(&unchanged))
	require.True(t, unchanged, "lifecycle A must not change the same user UUID in B")
}

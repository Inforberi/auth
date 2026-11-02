package projects_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func (f projectAccountFixture) httpUserLifecycle(t *testing.T, ctx context.Context, web projectAccountRequest, origin, actorToken string) {
	t.Helper()
	const target = "f8600000-0000-4000-8000-000000000001"
	const pending = "f8600000-0000-4000-8000-000000000002"
	const administrator = "f8600000-0000-4000-8000-000000000003"
	tokens := tokengenerate.New()
	raw, err := tokens.GenerateToken()
	require.NoError(t, err)
	_, err = f.db.Exec(ctx, `INSERT INTO auth.users(id,status) VALUES($1,'active'),($2,'pending'),($4,'active');
 INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Lifecycle fixture super administrator',true);
 INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'access.assignments.manage' FROM auth.roles WHERE key='super_admin';
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $4,id FROM auth.roles WHERE key='super_admin';
 INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($4,'lifecycle-admin@example.test',clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash)
 SELECT $4,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$4 AND p.user_id=$5::uuid;
 INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($4,$6,0);
 INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,user_agent,ip_address)
 VALUES($3,$1,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),'lifecycle-fixture','192.0.2.86')`, target, pending, tokens.Hash(raw), administrator, f.sourceUser, make([]byte, 48))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := f.db.Exec(cleanup, `DELETE FROM auth.account_status_audit WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.account_deletion_audit WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.user_roles WHERE user_id=ANY($1::uuid[]);
 DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
 DELETE FROM auth.role_permissions WHERE role_id IN(SELECT id FROM auth.roles WHERE key='super_admin');
 DELETE FROM auth.roles WHERE key='super_admin'`, []string{target, pending, administrator})
		require.NoError(t, err)
	})
	adminPath := "/api/v1/admin/users/" + administrator
	protected := web.commandMethod(t, "POST", adminPath+"/status", origin, actorToken, accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusBlocked, ExpectedAuthVersion: 1}, 409, nil)
	require.Contains(t, string(protected), `"code":"last_administrator"`)
	protected = web.commandMethod(t, "DELETE", adminPath, origin, actorToken, accounthttp.DeleteUserRequest{ExpectedAuthVersion: 1}, 409, nil)
	require.Contains(t, string(protected), `"code":"last_administrator"`)
	path := "/api/v1/admin/users/" + target
	block := accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusBlocked, ExpectedAuthVersion: 1}
	web.command(t, path+"/status", origin, "", block, 401, nil)
	web.command(t, path+"/status", "https://foreign.example.test", actorToken, block, 403, nil)
	web.command(t, path+"/status", origin, raw, block, 403, nil)
	web.commandMethod(t, "DELETE", path, origin, raw, accounthttp.DeleteUserRequest{ExpectedAuthVersion: 1}, 403, nil)
	var result accounthttp.UserLifecycleResponse
	web.command(t, path+"/status", origin, actorToken, block, 200, &result)
	require.EqualValues(t, 2, result.AuthVersion)
	var revoked bool
	require.NoError(t, f.db.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE token_hash=$1`, tokens.Hash(raw)).Scan(&revoked))
	require.True(t, revoked)
	status, _, _ := web("GET", "/api/v1/auth/me", origin, raw, "")
	require.Equal(t, 401, status)
	unblock := accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusActive, ExpectedAuthVersion: 1}
	web.command(t, path+"/status", origin, actorToken, unblock, 409, nil)
	unblock.ExpectedAuthVersion = 2
	web.command(t, path+"/status", origin, actorToken, unblock, 200, &result)
	require.EqualValues(t, 3, result.AuthVersion)
	status, _, _ = web("GET", "/api/v1/auth/me", origin, raw, "")
	require.Equal(t, 401, status, "unblocking must not revive the old session")
	web.command(t, "/api/v1/admin/users/"+pending+"/status", origin, actorToken, accounthttp.ChangeUserStatusRequest{Status: accountdomain.StatusActive, ExpectedAuthVersion: 1}, 409, nil)
	deletion := accounthttp.DeleteUserRequest{ExpectedAuthVersion: 3}
	web.commandMethod(t, "DELETE", path, origin, actorToken, deletion, 200, &result)
	require.EqualValues(t, 4, result.AuthVersion)
	web.commandMethod(t, "DELETE", path, origin, actorToken, deletion, 409, nil)
	deletion.ExpectedAuthVersion = 4
	web.commandMethod(t, "DELETE", path, origin, actorToken, deletion, 200, &result)
	require.EqualValues(t, 4, result.AuthVersion)
	unblock.ExpectedAuthVersion = 4
	web.command(t, path+"/status", origin, actorToken, unblock, 409, nil)
	var deleted bool
	var audits int
	require.NoError(t, f.db.QueryRow(ctx, `SELECT deleted_at IS NOT NULL,(SELECT count(*) FROM auth.account_deletion_audit WHERE user_id=$1) FROM auth.users WHERE id=$1`, target).Scan(&deleted, &audits))
	require.True(t, deleted)
	require.Equal(t, 1, audits, "authorized current-version deletion retry must not repeat the mutation")
}

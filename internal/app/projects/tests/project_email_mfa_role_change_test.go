package projects_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfahttp "github.com/Inforberi/financial-intelligence/internal/auth/mfa/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func checkEmailMFAChallengeRoleChange(t *testing.T, f emailMFAHTTPFixture, owner string) {
	t.Helper()
	ctx := t.Context()
	db := f.projects.databases[0]
	var role accessdomain.RoleID
	require.NoError(t, db.QueryRow(ctx, `SELECT id FROM auth.roles WHERE key='email_mfa_candidate'`).Scan(&role))
	_, err := db.Exec(ctx, `DELETE FROM auth.role_permissions WHERE role_id=$1`, role)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, httpIsolationUser, role)
	require.NoError(t, err)
	secret, err := f.mfa[0].Seal([]byte(httpIsolationUser + "\x00JBSWY3DPEHPK3PXP"))
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,0)`, httpIsolationUser, secret)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, httpIsolationUser, role)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.mfa_totp WHERE user_id=$1`, httpIsolationUser)
		require.NoError(t, err)
	})
	require.NoError(t, f.projects.deps.Redis.Del(ctx, f.prefix[0]+f.mfa[0].Digest("mfa-email-login:resend:"+httpIsolationUser)).Err())
	web := f.webs[0]
	path := "/api/v1/auth/mfa/email/login"
	response := web.call(t, ctx, "POST", path, web.origin, "", map[string]string{"email": httpIsolationEmail, "password": httpIsolationPassword})
	require.Equal(t, 202, response.status, string(response.body))
	var challenge mfahttp.ChallengeResponse
	require.NoError(t, json.Unmarshal(response.body, &challenge))
	name := mfahttp.EmailLoginCookie + "-" + string(f.projects.projects[0].Binding.ProjectID)
	cookie := response.cookie(t, name)
	f.trackCompletion(challenge.Challenge, strings.TrimPrefix(cookie, name+"="))
	code := f.code(t, "mfa-email-login:", challenge.Challenge)
	actor := accessservice.Principal{UserID: accountdomain.UserID(httpOwnerID), TokenHash: tokengenerate.New().Hash(strings.TrimPrefix(owner, "__Host-session="))}
	err = f.projects.deps.Registry.UsePool(ctx, f.projects.projects[0], func(ctx context.Context, pool *pgxpool.Pool) error {
		_, err := accesspostgres.NewWithMFA(pool, true).UpdateRole(ctx, accessservice.UpdateRoleInput{CreateRoleInput: accessservice.CreateRoleInput{Actor: actor, Key: "email_mfa_candidate", Name: "Email MFA candidate", Permissions: []accessdomain.PermissionKey{"auth.settings.manage"}}, RoleID: role, ExpectedVersion: 1})
		return err
	})
	require.NoError(t, err, "a TOTP-equipped member may receive administrative permissions")
	response = web.call(t, ctx, "POST", path+"/complete", web.origin, cookie, mfahttp.CompleteEmailLoginRequest{Challenge: challenge.Challenge, Code: code})
	require.Equal(t, 400, response.status, "a pre-promotion email challenge must not create an administrative session")
	for _, cookie := range response.cookies {
		require.Empty(t, cookie.Value)
	}
}

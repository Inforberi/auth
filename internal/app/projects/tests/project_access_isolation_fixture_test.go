package projects_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accesssettings "github.com/Inforberi/financial-intelligence/internal/access/settings"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

const (
	httpOwnerID      = "f8800000-0000-4000-8000-000000000090"
	httpManagerID    = "f8800000-0000-4000-8000-000000000091"
	httpForeignID    = "f8800000-0000-4000-8000-000000000092"
	httpOwnerEmail   = "http-owner@example.test"
	httpManagerEmail = "http-manager@example.test"
)

func TestTwoProjectAccessIsolationSQL(t *testing.T) {
	pair := prepareHTTPProjects(t)
	f := newProjectIsolationHTTP(t, pair.admin, pair.reader, pair.a, pair.b, pair.target)
	for _, db := range f.databases {
		seedHTTPAdministrators(t, t.Context(), db)
	}
	f.trackLogin(httpOwnerEmail)
	f.trackLogin(httpManagerEmail)
	for i := range f.projects {
		for _, id := range []string{httpOwnerID, httpManagerID} {
			f.redisKeys[f.passwordPrefix[i]+f.passwordCipher[i].Digest("reauth-user:"+id)] = struct{}{}
		}
	}
	catalog, err := accesssettings.NewCatalog([]accesssettings.Permission{{Key: "reports.read", Name: "Read"}, {Key: "reports.write", Name: "Write"}})
	require.NoError(t, err)
	webs, _, _ := f.serve(t, runtimeprofile.ProjectProfileConfig{BrowserEnabled: true, Password: &f.password, Access: &catalog, AuthSettingsEnabled: true, Timeout: 5 * time.Second})
	checkProjectAccessIsolation(t, t.Context(), f, webs)
	checkProjectSettingsIsolation(t, t.Context(), f, webs)
	checkPlatformRoleIsolation(t, t.Context(), pair, f)
}

func seedHTTPAdministrators(t *testing.T, ctx context.Context, db *pgx.Conn) {
	t.Helper()
	var mode string
	require.NoError(t, db.QueryRow(ctx, `SELECT mode FROM auth.mfa_settings`).Scan(&mode))
	_, err := db.Exec(ctx, `UPDATE auth.mfa_settings SET mode='optional'`)
	require.NoError(t, err)
	for _, person := range []struct{ id, email string }{{httpOwnerID, httpOwnerEmail}, {httpManagerID, httpManagerEmail}} {
		_, err := db.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, person.id)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp())`, person.id, person.email)
		require.NoError(t, err)
		_, err = db.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash)
 SELECT $1,e.id,p.password_hash FROM auth.user_emails e CROSS JOIN auth.password_credentials p WHERE e.user_id=$1 AND p.user_id=$2`, person.id, httpIsolationUser)
		require.NoError(t, err)
	}
	_, err = db.Exec(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Owner',true),('http_admin_manager','Manager',false)`)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key)
 SELECT id,unnest(ARRAY['access.roles.manage','access.assignments.manage','auth.settings.manage','accounts.users.read','reports.read']) FROM auth.roles WHERE key IN('super_admin','http_admin_manager')`)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'reports.write' FROM auth.roles WHERE key='super_admin'`)
	require.NoError(t, err)
	for id, key := range map[string]string{httpOwnerID: "super_admin", httpManagerID: "http_admin_manager"} {
		_, err := db.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key=$2`, id, key)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		for _, table := range []string{"access_audit", "auth_settings_audit", "password_audit"} {
			_, err := db.Exec(cleanup, `DELETE FROM auth.`+table+` WHERE actor_id=ANY($1::uuid[])`, []string{httpOwnerID, httpManagerID})
			require.NoError(t, err)
		}
		_, err := db.Exec(cleanup, `DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[])`, []string{httpOwnerID, httpManagerID})
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.users WHERE id=ANY($1::uuid[])`, []string{httpOwnerID, httpManagerID, httpForeignID})
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `DELETE FROM auth.roles WHERE key IN('super_admin','http_admin_manager','http_cross_reader','http_manager_reader','http_forbidden','http_stale_reader')`)
		require.NoError(t, err)
		_, err = db.Exec(cleanup, `UPDATE auth.mfa_settings SET mode=$1`, mode)
		require.NoError(t, err)
	})
}

func isolationAdminLogin(t *testing.T, ctx context.Context, web isolationHTTP, email string) string {
	t.Helper()
	response := web.call(t, ctx, "POST", "/api/v1/auth/login/email", web.origin, "", map[string]string{"email": email, "password": httpIsolationPassword})
	require.Equal(t, 200, response.status, "%s", response.body)
	cookie := response.cookie(t, "__Host-session")
	confirmed := web.call(t, ctx, "POST", "/api/v1/auth/reauthenticate/password", web.origin, cookie, map[string]string{"password": httpIsolationPassword})
	require.Equal(t, 200, confirmed.status, "%s", confirmed.body)
	return confirmed.cookie(t, "__Host-session")
}

func isolationCommand(t *testing.T, ctx context.Context, web isolationHTTP, method, path, cookie string, input any, expected int, output any) {
	t.Helper()
	response := web.call(t, ctx, method, path, web.origin, cookie, input)
	require.Equal(t, expected, response.status, "%s: %s", path, response.body)
	if output != nil {
		require.NoError(t, json.Unmarshal(response.body, output))
	}
}

func isolationRawCookie(cookie string) string { return strings.TrimPrefix(cookie, "__Host-session=") }

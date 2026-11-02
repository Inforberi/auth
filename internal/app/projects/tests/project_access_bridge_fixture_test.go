package projects_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func isolationPlatformOperator(t *testing.T, ctx context.Context, pair preparedHTTPProjects) (*catalog.Repository, operatordomain.Principal) {
	t.Helper()
	const role = "auth_platform_admin_isolation_test"
	var occupied bool
	require.NoError(t, pair.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&occupied))
	require.False(t, occupied, "fixture must not replace an existing role")
	_, err := pair.admin.Exec(ctx, `CREATE ROLE auth_platform_admin_isolation_test LOGIN NOINHERIT PASSWORD 'http-operator-fixture-only'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := pair.admin.Exec(cleanup, `DROP OWNED BY auth_platform_admin_isolation_test; DROP ROLE auth_platform_admin_isolation_test`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../../../.."
	}
	grants, err := os.ReadFile(filepath.Join(root, "deploy/platform-runtime-grants.sql"))
	require.NoError(t, err)
	_, err = pair.admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime", role, "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(string(grants)))
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(pair.admin.Config().ConnString())
	require.NoError(t, err)
	cfg.ConnConfig.User, cfg.ConnConfig.Password = role, "http-operator-fixture-only"
	cfg.MaxConns, cfg.MinConns = 2, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	authority, err := operators.New(pool, operatordomain.RealmID(pair.a.Binding.RealmID))
	require.NoError(t, err)
	require.NoError(t, authority.CheckRuntime(ctx, false))
	managed, err := catalog.NewManaged(pool, authority, 5*time.Minute, domain.CreationPolicy{
		AuthDomain: "example.test", PlatformOrigin: "https://platform-http.example.test", StorageTarget: "primary",
	})
	require.NoError(t, err)
	actor := operatordomain.Principal{UserID: accountdomain.UserID("d2000000-0000-4000-8000-000000000001"), TokenHash: strings.Repeat("d", 64)}
	// Synthetic fresh operator proof; project administrator accounts log in over HTTPS.
	_, err = pair.admin.Exec(ctx, `INSERT INTO auth.user_emails(id,user_id,email,verified_at) VALUES
 ('f8900000-0000-4000-8000-000000000001','d2000000-0000-4000-8000-000000000001','http-operator@example.test',clock_timestamp());
 INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES
 ('d2000000-0000-4000-8000-000000000001','f8900000-0000-4000-8000-000000000001','sql-fixture-hash');
 INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES
 ('d2000000-0000-4000-8000-000000000001',decode(repeat('11',64),'hex'),0)`)
	require.NoError(t, err)
	_, err = pair.admin.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
 primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
 VALUES($1,$2,1,statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '2 hours',
 'password',statement_timestamp(),statement_timestamp(),statement_timestamp(),'totp','HTTP isolation operator fixture','192.0.2.1')`, actor.TokenHash, actor.UserID)
	require.NoError(t, err)
	return managed, actor
}

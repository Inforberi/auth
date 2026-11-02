package auth

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

func TestProjectRuntimeAssemblySQL(t *testing.T) {
	dsn := os.Getenv("AUTH_PROJECT_RUNTIME_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires a dedicated auth_runtime_assembly_test database")
	}
	parsed, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	require.Equal(t, "auth_runtime_assembly_test", parsed.Database, "refusing non-dedicated database")
	require.Equal(t, "auth", parsed.User)
	require.Contains(t, []string{"/var/run/postgresql", "127.0.0.1"}, parsed.Host)
	ctx := t.Context()
	admin, err := pgx.ConnectConfig(ctx, parsed)
	require.NoError(t, err)
	defer func() { require.NoError(t, admin.Close(ctx)) }()
	var empty bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT to_regnamespace('auth') IS NULL AND to_regnamespace('platform') IS NULL
		AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='auth_runtime_assembly_reader')`).Scan(&empty))
	require.True(t, empty, "fixture must not replace existing data")
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../../.."
	}
	for _, name := range []string{"auth/000001_init.up.sql", "admin/000001_catalog.up.sql", "admin/000002_operators.up.sql"} {
		source, err := os.ReadFile(filepath.Join(root, "migrations", name))
		require.NoError(t, err)
		_, err = admin.Exec(ctx, string(source))
		require.NoError(t, err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `DROP SCHEMA platform CASCADE; DROP SCHEMA auth CASCADE;
			DROP OWNED BY auth_runtime_assembly_reader; DROP ROLE auth_runtime_assembly_reader`)
		require.NoError(t, err)
	}()
	_, err = admin.Exec(ctx, `REVOKE ALL ON SCHEMA auth FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC;
		REVOKE TEMP,CREATE ON DATABASE auth_runtime_assembly_test FROM PUBLIC;
		UPDATE platform.operator_realm SET id='c2000000-0000-4000-8000-000000000001';
		CREATE ROLE auth_runtime_assembly_reader LOGIN NOINHERIT PASSWORD 'assembly-fixture-only'`)
	require.NoError(t, err)
	grants, err := os.ReadFile(filepath.Join(root, "deploy/platform-runtime-reader-grants.sql"))
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime_reader", "auth_runtime_assembly_reader",
		"DATABASE auth_platform ", "DATABASE auth_runtime_assembly_test ").Replace(string(grants)))
	require.NoError(t, err)
	cfg := config.PlatformConfig{
		RealmID: "c2000000-0000-4000-8000-000000000001", StorageTarget: "primary",
		Runtime: config.ProjectRuntimeConfig{
			Enabled: true, CatalogURL: strings.Replace(dsn, "auth@", "auth_runtime_assembly_reader:assembly-fixture-only@", 1),
			MasterKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), MasterKeyID: "root-1",
			StorageHost: "/var/run/postgresql", StoragePort: 5432, MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1,
			MaxAcquiring: 2, AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute,
			SyncInterval: time.Minute, SyncTimeout: time.Second,
		},
	}
	owned := &resources{}
	defer owned.close()
	runtime, err := openProjectRuntime(ctx, cfg, owned)
	require.NoError(t, err)
	require.NoError(t, runtime.reader.CheckRuntime(ctx))
	t.Run("project delivery lifecycle", func(t *testing.T) { projectDeliveryLifecycleDrill(t, admin, cfg, runtime) })
	t.Run("project HTTP deployment", func(t *testing.T) { projectHTTPDeploymentDrill(t, cfg, runtime) })
	_, err = admin.Exec(ctx, `GRANT UPDATE(name) ON platform.projects TO auth_runtime_assembly_reader`)
	require.NoError(t, err)
	require.Error(t, runtime.reader.CheckRuntime(ctx))
	failed := &resources{}
	_, err = openProjectRuntime(ctx, cfg, failed)
	require.Error(t, err, "unsafe reader must fail startup")
	failed.close()
	_, err = admin.Exec(ctx, `REVOKE UPDATE(name) ON platform.projects FROM auth_runtime_assembly_reader`)
	require.NoError(t, err)
	owned.close()
	key := projectruntime.Key{Version: 1, Generation: 1, Binding: credentials.Binding{
		RealmID: projectdomain.ID(cfg.RealmID), ProjectID: "a2000000-0000-4000-8000-000000000001", ReservationID: "b2000000-0000-4000-8000-000000000001",
		StorageTarget: "primary", DatabaseOID: 1, OwnerOID: 2, RuntimeOID: 3, SchemaVersion: 1,
	}}
	require.ErrorIs(t, runtime.registry.Use(ctx, key, func(context.Context, projectruntime.Database) error {
		t.Error("closed registry called back")
		return nil
	}), projectruntime.ErrClosed)
	require.Eventually(t, func() bool {
		var gone bool
		err := admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='auth_runtime_assembly_reader')`).Scan(&gone)
		return err == nil && gone
	}, time.Second, 5*time.Millisecond, "both successful and failed assembly must release the private catalog pool")
}

package projects_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	runtimepostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime/repository/postgres"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func projectRuntimeDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal, command domain.RoleCreation,
	binding credentials.Binding, codec *credentials.Codec, env func(string) string, permissions settings.Catalog,
) {
	t.Helper()
	certPath := os.Getenv("AUTH_STORAGE_TEST_TLS_CA")
	if certPath == "" {
		t.Skip("requires explicit disposable PostgreSQL TLS certificate")
	}
	ctx := t.Context()
	command.OperationID, command.Key = "f2000000-0000-4000-8000-000000000016", "bridge_drill_registry"
	_, err := managed.PrepareRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `CREATE ROLE auth_platform_runtime_reader_test LOGIN NOINHERIT PASSWORD 'runtime-reader-fixture-only';
		REVOKE TEMP ON DATABASE auth_prepare_catalog_test FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		_, err := admin.Exec(cleanup, `DROP OWNED BY auth_platform_runtime_reader_test; DROP ROLE auth_platform_runtime_reader_test;
			GRANT TEMP ON DATABASE auth_prepare_catalog_test TO PUBLIC`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../../../.."
	}
	grants, err := os.ReadFile(filepath.Join(root, "deploy/postgres/grants/platform-runtime-reader-grants.sql"))
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime_reader", "auth_platform_runtime_reader_test",
		"DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(string(grants)))
	require.NoError(t, err)
	cfg, err := pgxpool.ParseConfig(strings.Replace(env("PROVISIONER_CATALOG_URL"),
		"auth_platform_preparation_test:catalog-fixture-only@", "auth_platform_runtime_reader_test:runtime-reader-fixture-only@", 1))
	require.NoError(t, err)
	cfg.MaxConns, cfg.MinConns = 1, 0
	private, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer private.Close()
	reader, err := runtimepostgres.NewRuntimeCredentialReader(private, binding.RealmID, codec)
	require.NoError(t, err)
	key := projectruntime.Key{Binding: binding, Version: command.ExpectedVersion, Generation: command.ExpectedGeneration}
	_, err = reader.LoadDatabaseCredential(ctx, key)
	require.NoError(t, err)
	stale := key
	stale.Generation++
	_, err = reader.LoadDatabaseCredential(ctx, stale)
	require.ErrorIs(t, err, domain.ErrConflict)
	var origin string
	require.NoError(t, admin.QueryRow(ctx, `SELECT origin FROM platform.projects WHERE id=$1`, binding.ProjectID).Scan(&origin))
	_, err = admin.Exec(ctx, `GRANT UPDATE(name) ON platform.projects TO auth_platform_runtime_reader_test`)
	require.NoError(t, err)
	_, err = reader.LoadDatabaseCredential(ctx, key)
	require.ErrorIs(t, err, domain.ErrConflict, "reader with extra write privileges must fail closed")
	resolved, err := reader.ResolveRuntime(ctx, origin)
	require.ErrorIs(t, err, domain.ErrUnavailable)
	require.Equal(t, projectruntime.Key{}, resolved)
	_, err = admin.Exec(ctx, `REVOKE UPDATE(name) ON platform.projects FROM auth_platform_runtime_reader_test`)
	require.NoError(t, err)
	_, err = private.Exec(ctx, `UPDATE platform.projects SET name=name`)
	require.Error(t, err)
	_, err = private.Exec(ctx, `SELECT id FROM auth.users`)
	require.Error(t, err)
	cert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	ca := x509.NewCertPool()
	require.True(t, ca.AppendCertsFromPEM(cert))
	target, err := projectruntime.NewTarget("127.0.0.1", 5432, &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	registry, err := projectruntime.New(projectruntime.Config{
		MaxRuntimes: 1, ConnectionsPerProject: 1, ConnectionBudget: 1, MaxAcquiring: 4,
		AcquireTimeout: time.Second, OpenTimeout: time.Second, IdleTimeout: time.Minute,
	}, map[string]projectruntime.Target{binding.StorageTarget: target}, reader, schemapostgres.CheckRuntimeConnection)
	require.NoError(t, err)
	defer func() { require.NoError(t, registry.Close(ctx)) }()
	probe := func(ctx context.Context, db projectruntime.Database) error {
		tx, err := db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var actual string
		var secure bool
		err = tx.QueryRow(ctx, `SELECT current_database(),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())`).Scan(&actual, &secure)
		require.NoError(t, err)
		require.Equal(t, "authp_"+strings.ReplaceAll(string(binding.ProjectID), "-", ""), actual)
		require.True(t, secure)
		return tx.Commit(ctx)
	}
	require.NoError(t, registry.Use(ctx, key, probe))
	t.Run("project HTTP authority", func(t *testing.T) { projectOriginHTTPDrill(t, admin, reader, registry, key, origin) })
	t.Run("project auth configuration", func(t *testing.T) { authConfigurationDrill(t, admin, reader, key, registry, codec) })
	t.Run("project SMTP source", func(t *testing.T) { projectSMTPDrill(t, admin, reader, key, registry) })
	t.Run("project password session", func(t *testing.T) { projectPasswordDrill(t, admin, reader, key, registry) })
	t.Run("resident state synchronization", func(t *testing.T) {
		runtimeSyncDrill(t, admin, reader, key, target)
	})
	grant, err := managed.AdmitRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	result, err := grant.ExecuteWithRuntime(ctx, registry, permissions, true)
	require.NoError(t, err)
	require.True(t, result.CatalogRecorded)
	t.Run("protected role outcome", func(t *testing.T) {
		roleOutcomeDrill(t, admin, managed, actor, command, registry, result)
	})
	t.Run("authority and transport faults", func(t *testing.T) {
		roleFaultDrill(t, admin, managed, actor, command, registry, key, reader, ca, permissions)
	})
	t.Run("concurrent role outcome authority", func(t *testing.T) {
		roleOutcomeConcurrencyDrill(t, admin, managed, actor, command, binding, registry, result)
	})
	t.Run("platform role HTTP bridge", func(t *testing.T) {
		roleHTTPDrill(t, admin, managed, actor, command, binding, registry, permissions)
	})
	registry.Invalidate(key)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, binding.ProjectID)
	require.NoError(t, err)
	require.ErrorIs(t, registry.Use(ctx, key, probe), projectruntime.ErrUnavailable)
	resolved, err = reader.ResolveRuntime(ctx, origin)
	require.ErrorIs(t, err, domain.ErrNotFound)
	require.Equal(t, projectruntime.Key{}, resolved)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, binding.ProjectID)
	require.NoError(t, err)
	require.NoError(t, registry.Use(ctx, key, probe))
	resolved, err = reader.ResolveRuntime(ctx, origin)
	require.NoError(t, err)
	require.Equal(t, key, resolved)
}

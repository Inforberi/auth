package main

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
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
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
		root = "../.."
	}
	grants, err := os.ReadFile(filepath.Join(root, "deploy/platform-runtime-reader-grants.sql"))
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
	reader, err := catalog.NewRuntimeCredentialReader(private, binding.RealmID, codec)
	require.NoError(t, err)
	key := projectruntime.Key{Binding: binding, Version: command.ExpectedVersion, Generation: command.ExpectedGeneration}
	_, err = reader.LoadDatabaseCredential(ctx, key)
	require.NoError(t, err)
	stale := key
	stale.Generation++
	_, err = reader.LoadDatabaseCredential(ctx, stale)
	require.ErrorIs(t, err, domain.ErrConflict)
	_, err = admin.Exec(ctx, `GRANT UPDATE(name) ON platform.projects TO auth_platform_runtime_reader_test`)
	require.NoError(t, err)
	_, err = reader.LoadDatabaseCredential(ctx, key)
	require.ErrorIs(t, err, domain.ErrConflict, "reader with extra write privileges must fail closed")
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
	}, map[string]projectruntime.Target{binding.StorageTarget: target}, reader, catalog.CheckRuntimeConnection)
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
	grant, err := managed.AdmitRoleCreation(ctx, actor, command)
	require.NoError(t, err)
	result, err := grant.ExecuteWithRuntime(ctx, registry, permissions, true)
	require.NoError(t, err)
	require.True(t, result.CatalogRecorded)
	registry.Invalidate(key)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, binding.ProjectID)
	require.NoError(t, err)
	require.ErrorIs(t, registry.Use(ctx, key, probe), projectruntime.ErrUnavailable)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled' WHERE id=$1`, binding.ProjectID)
	require.NoError(t, err)
	require.NoError(t, registry.Use(ctx, key, probe))
}

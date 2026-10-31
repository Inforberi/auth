package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func TestTwoProjectHTTPIsolationSQL(t *testing.T) {
	dsn := os.Getenv("AUTH_PREPARE_TEST_CATALOG_URL")
	if dsn == "" {
		t.Skip("requires explicit disposable catalog/storage/Redis/TLS fixture")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	physical, err := pgx.Connect(ctx, os.Getenv("AUTH_STORAGE_TEST_DATABASE_URL"))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		require.NoError(t, physical.Close(cleanup))
		require.NoError(t, admin.Close(cleanup))
	})
	require.Equal(t, "auth_prepare_catalog_test", admin.Config().Database)
	require.Equal(t, "auth_storage_test", physical.Config().Database)
	var occupied bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN
 ('auth_storage_executor','auth_platform_preparation_test','auth_platform_runtime_reader_test'))
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN('auth','platform'))`).Scan(&occupied))
	require.False(t, occupied, "fixture must not replace existing roles or catalog")
	require.NoError(t, physical.QueryRow(ctx, `SELECT to_regnamespace('provisioning') IS NOT NULL`).Scan(&occupied))
	require.False(t, occupied)
	_, err = admin.Exec(ctx, `CREATE ROLE auth_platform_preparation_test LOGIN PASSWORD 'catalog-fixture-only';
 CREATE ROLE auth_storage_executor LOGIN PASSWORD 'storage-fixture-only' CREATEDB CREATEROLE NOINHERIT;
 CREATE ROLE auth_platform_runtime_reader_test LOGIN NOINHERIT PASSWORD 'runtime-reader-fixture-only'`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, err := physical.Exec(cleanup, `DROP OWNED BY auth_storage_executor; DROP SCHEMA IF EXISTS provisioning CASCADE; DROP ROLE auth_storage_executor`)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DROP OWNED BY auth_platform_runtime_reader_test; DROP ROLE auth_platform_runtime_reader_test;
 DROP OWNED BY auth_platform_preparation_test; DROP SCHEMA IF EXISTS platform CASCADE;
 DROP SCHEMA IF EXISTS auth CASCADE; DROP ROLE auth_platform_preparation_test`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../.."
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, path))
		require.NoError(t, err)
		return string(data)
	}
	for _, path := range []string{"migrations/000001_init.up.sql", "migrations/platform/000001_catalog.up.sql", "migrations/platform/000002_operators.up.sql"} {
		_, err := admin.Exec(ctx, read(path))
		require.NoError(t, err)
	}
	_, err = admin.Exec(ctx, `REVOKE ALL ON SCHEMA auth FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC;
 REVOKE CREATE,TEMP ON DATABASE auth_prepare_catalog_test FROM PUBLIC;
 INSERT INTO auth.users(id) VALUES('d2000000-0000-4000-8000-000000000001');
 UPDATE platform.operator_realm SET id='c2000000-0000-4000-8000-000000000001',initialized_at=now(),first_operator_id='d2000000-0000-4000-8000-000000000001';
 INSERT INTO platform.operator_permissions(user_id,permission_key) SELECT 'd2000000-0000-4000-8000-000000000001',
 unnest(ARRAY['platform.projects.read','platform.projects.manage','platform.project_users.manage','platform.project_access.manage','platform.project_settings.manage','platform.operators.manage'])`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_preparation", "auth_platform_preparation_test", "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(read("deploy/platform-preparation-grants.sql")))
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_runtime_reader", "auth_platform_runtime_reader_test", "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(read("deploy/platform-runtime-reader-grants.sql")))
	require.NoError(t, err)
	_, err = physical.Exec(ctx, strings.NewReplacer(":'realm'", "'c2000000-0000-4000-8000-000000000001'", ":'target'", "'primary'").Replace(read("deploy/storage-target.sql")))
	require.NoError(t, err)
	master := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	env := func(name string) string {
		return map[string]string{
			"PROVISIONER_CATALOG_URL":    strings.Replace(dsn, "auth@", "auth_platform_preparation_test:catalog-fixture-only@", 1),
			"PROVISIONER_STORAGE_URL":    strings.Replace(os.Getenv("AUTH_STORAGE_TEST_DATABASE_URL"), "auth@", "auth_storage_executor:storage-fixture-only@", 1),
			"PROVISIONER_REALM_ID":       "c2000000-0000-4000-8000-000000000001",
			"PROVISIONER_STORAGE_TARGET": "primary",
			"PROVISIONER_MASTER_KEY":     master,
			"PROVISIONER_MASTER_KEY_ID":  "root-1",
		}[name]
	}
	codec, err := credentials.New(master, "root-1")
	require.NoError(t, err)
	cert, err := os.ReadFile(os.Getenv("AUTH_STORAGE_TEST_TLS_CA"))
	require.NoError(t, err)
	ca := x509.NewCertPool()
	require.True(t, ca.AppendCertsFromPEM(cert))
	// Release each preparation session/DDL lock before preparing the next independent project.
	a := prepareHTTPPeer(t, ctx, admin, env, codec, ca, "a2000000-0000-4000-8000-000000000001", "b2000000-0000-4000-8000-000000000001", "https://test.example.test")
	b := prepareHTTPPeer(t, ctx, admin, env, codec, ca, httpPeerProject, "b2000000-0000-4000-8000-000000000088", "https://http-peer.example.test")
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "auth_platform_runtime_reader_test", "runtime-reader-fixture-only"
	cfg.MaxConns, cfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	reader, err := catalog.NewRuntimeCredentialReader(pool, a.Binding.RealmID, codec)
	require.NoError(t, err)
	require.NoError(t, reader.CheckRuntime(ctx))
	target, err := projectruntime.NewTarget("127.0.0.1", physical.Config().Port, &tls.Config{RootCAs: ca, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	projectHTTPIsolationDrill(t, admin, reader, a, b, target)
}

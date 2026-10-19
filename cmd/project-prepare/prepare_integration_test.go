package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestPrepareCommandSQL(t *testing.T) {
	dsn := os.Getenv("AUTH_PREPARE_TEST_CATALOG_URL")
	if dsn == "" {
		t.Skip("requires separate disposable catalog and storage databases")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	physical, err := pgx.Connect(ctx, os.Getenv("AUTH_STORAGE_TEST_DATABASE_URL"))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		require.NoError(t, physical.Close(cleanup))
		require.NoError(t, admin.Close(cleanup))
	})
	var name string
	require.NoError(t, admin.QueryRow(ctx, `SELECT current_database()`).Scan(&name))
	require.Equal(t, "auth_prepare_catalog_test", name)
	require.NoError(t, physical.QueryRow(ctx, `SELECT current_database()`).Scan(&name))
	require.Equal(t, "auth_storage_test", name)
	var occupied bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('auth_storage_executor','auth_platform_preparation_test'))
		OR EXISTS(SELECT 1 FROM pg_database WHERE datname='authp_a2000000000040008000000000000001')
		OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname='autho_a2000000000040008000000000000001')
		OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','platform'))`).Scan(&occupied))
	require.False(t, occupied, "fixture must not replace existing objects")
	require.NoError(t, physical.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='provisioning')`).Scan(&occupied))
	require.False(t, occupied)
	_, err = admin.Exec(ctx, `CREATE ROLE auth_platform_preparation_test LOGIN PASSWORD 'catalog-fixture-only';
		CREATE ROLE auth_storage_executor LOGIN PASSWORD 'storage-fixture-only' CREATEDB CREATEROLE NOINHERIT`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		_, err := physical.Exec(cleanup, `DROP DATABASE IF EXISTS authp_a2000000000040008000000000000001`)
		require.NoError(t, err)
		_, err = physical.Exec(cleanup, `DROP ROLE IF EXISTS autho_a2000000000040008000000000000001;
			DROP OWNED BY auth_storage_executor; DROP SCHEMA IF EXISTS provisioning CASCADE; DROP ROLE auth_storage_executor`)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DROP OWNED BY auth_platform_preparation_test; DROP SCHEMA IF EXISTS platform CASCADE;
			DROP SCHEMA IF EXISTS auth CASCADE; DROP ROLE auth_platform_preparation_test`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../.."
	}
	read := func(path string) string {
		source, err := os.ReadFile(filepath.Join(root, path))
		require.NoError(t, err)
		return string(source)
	}
	for _, path := range []string{"migrations/000001_init.up.sql", "migrations/platform/000001_catalog.up.sql", "migrations/platform/000002_operators.up.sql"} {
		_, err = admin.Exec(ctx, read(path))
		require.NoError(t, err)
	}
	_, err = admin.Exec(ctx, `REVOKE ALL ON SCHEMA auth FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC;
		REVOKE CREATE ON DATABASE auth_prepare_catalog_test FROM PUBLIC;
		INSERT INTO auth.users(id) VALUES('d2000000-0000-4000-8000-000000000001');
		UPDATE platform.operator_realm SET id='c2000000-0000-4000-8000-000000000001',initialized_at=now(),first_operator_id='d2000000-0000-4000-8000-000000000001';
		INSERT INTO platform.projects(id,slug,name,origin,storage_target) VALUES('a2000000-0000-4000-8000-000000000001','test-project','Test project','https://test.example.test','primary')`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_preparation", "auth_platform_preparation_test", "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(read("deploy/platform-preparation-grants.sql")))
	require.NoError(t, err)
	_, err = physical.Exec(ctx, strings.NewReplacer(":'realm'", "'c2000000-0000-4000-8000-000000000001'", ":'target'", "'primary'").Replace(read("deploy/storage-target.sql")))
	require.NoError(t, err)
	storageURL := strings.Replace(os.Getenv("AUTH_STORAGE_TEST_DATABASE_URL"), "auth@", "auth_storage_executor:storage-fixture-only@", 1)
	catalogURL := strings.Replace(dsn, "auth@", "auth_platform_preparation_test:catalog-fixture-only@", 1)
	env := func(key string) string {
		return map[string]string{
			"PROVISIONER_CATALOG_URL": catalogURL, "PROVISIONER_STORAGE_URL": storageURL,
			"PROVISIONER_REALM_ID": "c2000000-0000-4000-8000-000000000001", "PROVISIONER_STORAGE_TARGET": "primary",
		}[key]
	}
	args := []string{"-project", "a2000000-0000-4000-8000-000000000001", "-operation", "b2000000-0000-4000-8000-000000000001", "-version", "1", "-generation", "1"}
	var first, second bytes.Buffer
	require.NoError(t, run(ctx, args, env, &first, io.Discard))
	require.Contains(t, first.String(), `"stage":"database_sealed"`)
	require.NoError(t, run(ctx, args, env, &second, io.Discard))
	require.Equal(t, first.String(), second.String())
	var phase string
	var version int64
	require.NoError(t, admin.QueryRow(ctx, `SELECT phase,version FROM platform.projects`).Scan(&phase, &version))
	require.Equal(t, "provisioning", phase)
	require.EqualValues(t, 2, version, "command must not publish ready")
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1,generation=generation+1`)
	require.NoError(t, err)
	require.Error(t, run(ctx, args, env, io.Discard, io.Discard), "stale catalog receipt cannot start storage")
}

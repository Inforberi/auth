package projects_test

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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	preparationcli "github.com/Inforberi/financial-intelligence/internal/admin/projects/preparation/transport/cli"
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
		OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authr_a2000000000040008000000000000001')
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
			DROP ROLE IF EXISTS authr_a2000000000040008000000000000001;
			DROP OWNED BY auth_storage_executor; DROP SCHEMA IF EXISTS provisioning CASCADE; DROP ROLE auth_storage_executor`)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DROP OWNED BY auth_platform_preparation_test; DROP SCHEMA IF EXISTS platform CASCADE;
			DROP SCHEMA IF EXISTS auth CASCADE; DROP ROLE auth_platform_preparation_test`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../../../.."
	}
	read := func(path string) string {
		source, err := os.ReadFile(filepath.Join(root, path))
		require.NoError(t, err)
		return string(source)
	}
	for _, path := range []string{"migrations/auth/000001_init.up.sql", "migrations/admin/000001_catalog.up.sql", "migrations/admin/000002_operators.up.sql"} {
		_, err = admin.Exec(ctx, read(path))
		require.NoError(t, err)
	}
	_, err = admin.Exec(ctx, `REVOKE ALL ON SCHEMA auth FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC;
		REVOKE CREATE ON DATABASE auth_prepare_catalog_test FROM PUBLIC;
		INSERT INTO auth.users(id) VALUES('d2000000-0000-4000-8000-000000000001');
		UPDATE platform.operator_realm SET id='c2000000-0000-4000-8000-000000000001',initialized_at=now(),first_operator_id='d2000000-0000-4000-8000-000000000001';
		INSERT INTO platform.projects(id,slug,name,origin,storage_target) VALUES('a2000000-0000-4000-8000-000000000001','test-project','Test project','https://test.example.test','primary')`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, strings.NewReplacer("auth_platform_preparation", "auth_platform_preparation_test", "DATABASE auth_platform ", "DATABASE auth_prepare_catalog_test ").Replace(read("deploy/postgres/grants/platform-preparation-grants.sql")))
	require.NoError(t, err)
	_, err = physical.Exec(ctx, strings.NewReplacer(":'realm'", "'c2000000-0000-4000-8000-000000000001'", ":'target'", "'primary'").Replace(read("deploy/postgres/storage-target.sql")))
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
	require.NoError(t, preparationcli.Run(ctx, args, env, &first, io.Discard, runPreparationCommand))
	require.Contains(t, first.String(), `"stage":"database_sealed"`)
	require.NoError(t, preparationcli.Run(ctx, args, env, &second, io.Discard, runPreparationCommand))
	require.Equal(t, first.String(), second.String())
	projectConfig := physical.Config().Copy()
	projectConfig.Database = "authp_a2000000000040008000000000000001"
	inspect := func(check func(*pgx.Conn)) {
		_, err := physical.Exec(ctx, `ALTER DATABASE authp_a2000000000040008000000000000001 ALLOW_CONNECTIONS true`)
		require.NoError(t, err)
		conn, err := pgx.ConnectConfig(ctx, projectConfig)
		require.NoError(t, err)
		defer func() {
			require.NoError(t, conn.Close(ctx))
			_, err := physical.Exec(ctx, `ALTER DATABASE authp_a2000000000040008000000000000001 ALLOW_CONNECTIONS false`)
			require.NoError(t, err)
		}()
		check(conn)
	}
	// A failure after runtime CREATE ROLE must roll back that role and the whole schema.
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `CREATE FUNCTION public.fail_schema() RETURNS event_trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'fixture schema failure'; END;$$;
			CREATE EVENT TRIGGER fail_schema ON ddl_command_start WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.fail_schema()`)
		require.NoError(t, err)
	})
	schemaArgs := append(append([]string{}, args...), "-schema")
	require.Error(t, preparationcli.Run(ctx, schemaArgs, env, io.Discard, io.Discard, runPreparationCommand))
	inspect(func(conn *pgx.Conn) {
		var absent bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','project_meta'))
			AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='authr_a2000000000040008000000000000001')`).Scan(&absent))
		require.True(t, absent)
		_, err := conn.Exec(ctx, `DROP EVENT TRIGGER fail_schema; DROP FUNCTION public.fail_schema()`)
		require.NoError(t, err)
	})
	var installed, replayed bytes.Buffer
	require.NoError(t, preparationcli.Run(ctx, schemaArgs, env, &installed, io.Discard, runPreparationCommand))
	require.Contains(t, installed.String(), `"stage":"schema_prepared"`)
	require.Contains(t, installed.String(), `"schemaVersion":1`)
	require.NoError(t, preparationcli.Run(ctx, schemaArgs, env, &replayed, io.Discard, runPreparationCommand))
	require.Equal(t, installed.String(), replayed.String())
	operatorSecretsProfileDrill(t, admin, env, read)
	secretsPreparationDrill(t, admin, physical, env, schemaArgs)
	var closed bool
	require.NoError(t, physical.QueryRow(ctx, `SELECT NOT datallowconn FROM pg_database WHERE datname='authp_a2000000000040008000000000000001'`).Scan(&closed))
	require.True(t, closed)
	inspect(func(conn *pgx.Conn) {
		var valid bool
		require.NoError(t, conn.QueryRow(ctx, `SELECT NOT r.rolcanlogin AND NOT r.rolcreatedb AND NOT r.rolcreaterole
			AND NOT pg_has_role(r.oid,(SELECT oid FROM pg_roles WHERE rolname='autho_a2000000000040008000000000000001'),'MEMBER')
			AND NOT has_database_privilege(r.oid,current_database(),'CONNECT,CREATE,TEMP')
			AND NOT has_database_privilege(r.oid,'auth_storage_test','CONNECT')
			AND NOT has_schema_privilege(r.oid,'project_meta','USAGE')
			AND has_table_privilege(r.oid,'auth.users','SELECT')
			AND NOT has_table_privilege(r.oid,'auth.restore_audit','INSERT,UPDATE,DELETE')
			FROM pg_roles r WHERE rolname='authr_a2000000000040008000000000000001'`).Scan(&valid))
		require.True(t, valid)
		for _, statement := range []string{`CREATE TABLE auth.forbidden(id int)`, `INSERT INTO auth.restore_audit DEFAULT VALUES`, `SELECT * FROM project_meta.identity`} {
			tx, err := conn.Begin(ctx)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SET LOCAL ROLE authr_a2000000000040008000000000000001`)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, statement)
			require.Error(t, err, statement)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, "42501", denied.Code, statement)
			require.NoError(t, tx.Rollback(ctx))
		}
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `SET LOCAL ROLE authr_a2000000000040008000000000000001;
			INSERT INTO auth.users(id) VALUES('e2000000-0000-4000-8000-000000000001');
			UPDATE auth.users SET status='blocked' WHERE id='e2000000-0000-4000-8000-000000000001';
			DELETE FROM auth.users WHERE id='e2000000-0000-4000-8000-000000000001'`)
		require.NoError(t, err)
		require.NoError(t, tx.Rollback(ctx))
		_, err = conn.Exec(ctx, `UPDATE project_meta.identity SET project_id='a2000000-0000-4000-8000-000000000099'`)
		require.NoError(t, err)
	})
	require.ErrorIs(t, preparationcli.Run(ctx, schemaArgs, env, io.Discard, io.Discard, runPreparationCommand), domain.ErrConflict, "wrong schema marker must not be adopted")
	require.NoError(t, physical.QueryRow(ctx, `SELECT NOT datallowconn FROM pg_database WHERE datname='authp_a2000000000040008000000000000001'`).Scan(&closed))
	require.True(t, closed, "failure cleanup must reseal the database")
	var phase string
	var version int64
	require.NoError(t, admin.QueryRow(ctx, `SELECT phase,version FROM platform.projects`).Scan(&phase, &version))
	require.Equal(t, "provisioning", phase)
	require.EqualValues(t, 2, version, "command must not publish ready")
	inspect(func(conn *pgx.Conn) {
		_, err := conn.Exec(ctx, `UPDATE project_meta.identity SET project_id='a2000000-0000-4000-8000-000000000001'`)
		require.NoError(t, err)
		locked, err := conn.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = locked.Rollback(context.WithoutCancel(ctx)) }()
		_, err = locked.Exec(ctx, `LOCK TABLE project_meta.identity IN ACCESS EXCLUSIVE MODE`)
		require.NoError(t, err)
		finished := make(chan error, 1)
		go func() {
			finished <- preparationcli.Run(ctx, schemaArgs, env, io.Discard, io.Discard, runPreparationCommand)
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		wait, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		for {
			var blocked bool
			require.NoError(t, physical.QueryRow(wait, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				WHERE usename='auth_storage_executor' AND $1::int=ANY(pg_blocking_pids(pid)))`, conn.PgConn().PID()).Scan(&blocked))
			if blocked {
				break
			}
			select {
			case err := <-finished:
				t.Fatalf("schema returned before the marker lock: %v", err)
			case <-wait.Done():
				t.Fatal("schema did not reach the marker lock")
			case <-ticker.C:
			}
		}
		_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended',version=version+1,generation=generation+1`)
		require.NoError(t, err)
		require.NoError(t, locked.Rollback(ctx))
		require.ErrorIs(t, <-finished, domain.ErrConflict, "final catalog authority must be rechecked after schema work")
		require.NoError(t, physical.QueryRow(ctx, `SELECT NOT datallowconn FROM pg_database WHERE datname='authp_a2000000000040008000000000000001'`).Scan(&closed))
		require.True(t, closed)
	})
	require.Error(t, preparationcli.Run(ctx, args, env, io.Discard, io.Discard, runPreparationCommand), "stale catalog receipt cannot start storage")
}

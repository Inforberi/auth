package postgres

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func TestTargetBounds(t *testing.T) {
	_, err := New(nil, "", "")
	require.ErrorIs(t, err, ErrUnavailable)
	target := &Target{name: "primary"}
	_, err = target.Prepare(t.Context(), domain.PreparationReservation{})
	require.ErrorIs(t, err, domain.ErrConflict)
	_, err = target.InstallSchema(t.Context(), nil)
	require.ErrorIs(t, err, domain.ErrConflict)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, unavailable(ctx), context.Canceled)
	require.ErrorIs(t, unavailable(ctx), ErrUnavailable)
}

func TestStoragePreparationSQL(t *testing.T) {
	dsn := os.Getenv("AUTH_STORAGE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires an isolated auth_storage_test database and privileged fixture LOGIN")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer stop()
		require.NoError(t, admin.Close(cleanup))
	})
	var database string
	require.NoError(t, admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	require.Equal(t, "auth_storage_test", database, "refuse working databases")
	var exists bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='auth_storage_executor')
		OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='provisioning')`).Scan(&exists))
	require.False(t, exists, "fixture must not replace an existing role/schema")
	r := domain.PreparationReservation{ProjectID: "a1000000-0000-4000-8000-000000000001", ReservationID: "b1000000-0000-4000-8000-000000000001", StorageTarget: "primary", Generation: 2}
	other := r
	other.ProjectID = "a1000000-0000-4000-8000-000000000002"
	for _, item := range []domain.PreparationReservation{r, other} {
		db, role, err := item.ResourceNames()
		require.NoError(t, err)
		require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)
			OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$2)`, db, role).Scan(&exists))
		require.False(t, exists, "fixture names must be absent")
	}
	_, err = admin.Exec(ctx, `CREATE ROLE auth_storage_executor LOGIN PASSWORD 'storage-fixture-only' CREATEDB CREATEROLE NOINHERIT`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer stop()
		for _, item := range []domain.PreparationReservation{r, other} {
			db, role, err := item.ResourceNames()
			require.NoError(t, err)
			_, err = admin.Exec(cleanup, `DROP DATABASE IF EXISTS `+pgx.Identifier{db}.Sanitize())
			require.NoError(t, err)
			_, err = admin.Exec(cleanup, `DROP ROLE IF EXISTS `+pgx.Identifier{role}.Sanitize())
			require.NoError(t, err)
		}
		_, err = admin.Exec(cleanup, `DROP OWNED BY auth_storage_executor; DROP SCHEMA IF EXISTS provisioning CASCADE; DROP ROLE auth_storage_executor`)
		require.NoError(t, err)
	})
	root := os.Getenv("AUTH_STORAGE_TEST_ROOT")
	if root == "" {
		root = "../../../../.."
	}
	script, err := os.ReadFile(filepath.Join(root, "deploy/storage-target.sql"))
	require.NoError(t, err)
	realm := domain.ID("c1000000-0000-4000-8000-000000000001")
	sql := strings.ReplaceAll(string(script), ":'realm'", "'"+string(realm)+"'")
	sql = strings.ReplaceAll(sql, ":'target'", "'primary'")
	_, err = admin.Exec(ctx, sql)
	require.NoError(t, err)
	cfg := admin.Config().Copy()
	cfg.User, cfg.Password = "auth_storage_executor", "storage-fixture-only"
	cfg.RuntimeParams = map[string]string{"statement_timeout": "10000", "lock_timeout": "500", "idle_in_transaction_session_timeout": "5000"}
	open := func() *Target {
		conn, err := pgx.ConnectConfig(ctx, cfg)
		require.NoError(t, err)
		target, err := New(conn, realm, "primary")
		require.NoError(t, err)
		return target
	}
	prepare := func(input domain.PreparationReservation) (Resources, error) {
		target := open()
		defer func() { require.NoError(t, target.conn.Close(context.WithoutCancel(ctx))) }()
		return target.Prepare(ctx, input)
	}
	ownerTarget, err := New(admin, realm, "primary")
	require.NoError(t, err)
	require.ErrorIs(t, ownerTarget.CheckRuntime(ctx), ErrUnavailable)
	resources, err := prepare(r)
	require.NoError(t, err)
	var sealed, publicBlocked bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT datallowconn,NOT EXISTS(
		SELECT 1 FROM aclexplode(datacl) WHERE grantee=0) FROM pg_database WHERE oid=$1`, resources.DatabaseOID).Scan(&sealed, &publicBlocked))
	require.True(t, sealed)
	require.True(t, publicBlocked)
	var before, after string
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM provisioning.resources WHERE project_id=$1`, r.ProjectID).Scan(&before))
	replayed, err := prepare(r)
	require.NoError(t, err)
	require.Equal(t, resources, replayed)
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM provisioning.resources WHERE project_id=$1`, r.ProjectID).Scan(&after))
	require.Equal(t, before, after, "replay must not update the ledger")
	_, err = admin.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` ALLOW_CONNECTIONS true`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.ErrorIs(t, err, domain.ErrConflict, "open database without schema intent must not be adopted")
	_, err = admin.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` ALLOW_CONNECTIONS false`)
	require.NoError(t, err)
	interrupted := open()
	prepared, err := interrupted.Prepare(ctx, r)
	require.NoError(t, err)
	require.NoError(t, interrupted.schemaAccess(ctx, r, prepared, true))
	require.NoError(t, interrupted.conn.Close(ctx))
	_, err = admin.Exec(ctx, `GRANT CONNECT ON DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` TO PUBLIC`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.ErrorIs(t, err, domain.ErrConflict, "schema intent is not permission to accept unsafe ACL")
	_, err = admin.Exec(ctx, `REVOKE CONNECT ON DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` FROM PUBLIC`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.NoError(t, err, "lost response after opening schema access can be safely resealed")
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT datallowconn AND NOT has_database_privilege('auth_storage_executor',oid,'CONNECT')
		FROM pg_database WHERE oid=$1`, resources.DatabaseOID).Scan(&sealed))
	require.True(t, sealed)
	stale := r
	stale.Generation--
	_, err = prepare(stale)
	require.ErrorIs(t, err, domain.ErrConflict)
	wrong := r
	wrong.ReservationID = "b1000000-0000-4000-8000-000000000099"
	_, err = prepare(wrong)
	require.ErrorIs(t, err, domain.ErrConflict)
	wrongTarget := open()
	wrongTarget.name = "other"
	require.ErrorIs(t, wrongTarget.CheckRuntime(ctx), ErrUnavailable)
	require.NoError(t, wrongTarget.conn.Close(ctx))
	_, err = admin.Exec(ctx, `GRANT UPDATE(reservation_id) ON provisioning.resources TO auth_storage_executor`)
	require.NoError(t, err)
	excess := open()
	require.ErrorIs(t, excess.CheckRuntime(ctx), ErrUnavailable)
	require.NoError(t, excess.conn.Close(ctx))
	_, err = admin.Exec(ctx, `REVOKE UPDATE(reservation_id) ON provisioning.resources FROM auth_storage_executor`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `SELECT pg_advisory_lock(1096111176,1)`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.ErrorIs(t, err, ErrBusy)
	_, err = admin.Exec(ctx, `SELECT pg_advisory_unlock(1096111176,1)`)
	require.NoError(t, err)
	blocked, err := admin.Begin(ctx)
	require.NoError(t, err)
	_, err = blocked.Exec(ctx, `SELECT project_id FROM provisioning.resources WHERE project_id=$1 FOR UPDATE`, r.ProjectID)
	require.NoError(t, err)
	waiting := open()
	deadline, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = waiting.Prepare(deadline, r)
	stop()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, waiting.conn.Close(ctx))
	require.NoError(t, blocked.Rollback(ctx))
	_, err = admin.Exec(ctx, `ALTER ROLE `+pgx.Identifier{resources.Owner}.Sanitize()+` LOGIN`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.ErrorIs(t, err, domain.ErrConflict, "changed owner attributes")
	_, err = admin.Exec(ctx, `ALTER ROLE `+pgx.Identifier{resources.Owner}.Sanitize()+` NOLOGIN`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` OWNER TO auth`)
	require.NoError(t, err)
	_, err = prepare(r)
	require.ErrorIs(t, err, domain.ErrConflict, "changed actual database owner")
	_, err = admin.Exec(ctx, `ALTER DATABASE `+pgx.Identifier{resources.Database}.Sanitize()+` OWNER TO `+pgx.Identifier{resources.Owner}.Sanitize())
	require.NoError(t, err)
	// Simulate lost DDL reply: the database exists but storing its OID fails.
	other.ReservationID = "b1000000-0000-4000-8000-000000000002"
	_, err = admin.Exec(ctx, `ALTER TABLE provisioning.resources ADD CONSTRAINT fail_oid CHECK(project_id<>'a1000000-0000-4000-8000-000000000002' OR database_oid IS NULL)`)
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, ErrUnavailable)
	var created uint32
	db, role, err := other.ResourceNames()
	require.NoError(t, err)
	require.NoError(t, admin.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname=$1 AND NOT datallowconn`, db).Scan(&created))
	_, err = admin.Exec(ctx, `ALTER TABLE provisioning.resources DROP CONSTRAINT fail_oid`)
	require.NoError(t, err)
	resumed, err := prepare(other)
	require.NoError(t, err)
	require.Equal(t, created, resumed.DatabaseOID)
	// An OID already stored is not replaced if the database disappears later.
	_, err = admin.Exec(ctx, `DROP DATABASE `+pgx.Identifier{db}.Sanitize())
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, domain.ErrConflict, "a recorded database may not be silently recreated")
	_, err = admin.Exec(ctx, `DELETE FROM provisioning.resources WHERE project_id=$1`, other.ProjectID)
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, domain.ErrConflict, "a surviving role is not adopted after metadata loss")
	_, err = admin.Exec(ctx, `DROP ROLE `+pgx.Identifier{role}.Sanitize())
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `ALTER TABLE provisioning.resources ADD CONSTRAINT fail_insert CHECK(project_id<>'a1000000-0000-4000-8000-000000000002')`)
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, ErrUnavailable)
	require.NoError(t, admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists))
	require.False(t, exists, "role creation must roll back with its ledger INSERT")
	_, err = admin.Exec(ctx, `ALTER TABLE provisioning.resources DROP CONSTRAINT fail_insert`)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` NOLOGIN`)
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, domain.ErrConflict, "name-only role collision")
	_, err = admin.Exec(ctx, `DROP ROLE `+pgx.Identifier{role}.Sanitize())
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{db}.Sanitize()+` TEMPLATE template0 ALLOW_CONNECTIONS false`)
	require.NoError(t, err)
	_, err = prepare(other)
	require.ErrorIs(t, err, domain.ErrConflict, "name-only database collision")
}

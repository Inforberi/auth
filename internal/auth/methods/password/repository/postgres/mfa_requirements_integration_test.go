package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestMFARequirementPredicatesSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	const user = "fa630000-0000-4000-8000-000000000001"
	accessExec(t, db, ctx, `INSERT INTO auth.users(id) VALUES($1)`, user)
	accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name) VALUES('requirement_fixture','Requirement fixture')`)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='requirement_fixture'`, user)
	read := func(t *testing.T, admin, mfa, role bool) {
		t.Helper()
		var gotAdmin, gotMFA, gotRole bool
		err := db.QueryRow(ctx, `SELECT auth.has_administrative_access($1),
 auth.administrative_mfa_required($1),auth.role_requires_mfa($1)`, user).Scan(&gotAdmin, &gotMFA, &gotRole)
		require.NoError(t, err)
		require.Equal(t, admin, gotAdmin)
		require.Equal(t, mfa, gotMFA)
		require.Equal(t, role, gotRole)
	}
	read(t, false, false, false)
	for _, permission := range []string{
		"access.roles.manage", "access.assignments.manage", "accounts.email.bind", "accounts.users.manage",
		"accounts.users.read", "accounts.users.status.manage", "accounts.users.delete", "auth.settings.manage", "reports.read",
	} {
		t.Run(permission, func(t *testing.T) {
			accessExec(t, db, ctx, `DELETE FROM auth.role_permissions`)
			accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,$1 FROM auth.roles WHERE key='requirement_fixture'`, permission)
			read(t, permission != "reports.read", permission != "reports.read" && permission != "accounts.users.read", false)
		})
	}
	accessExec(t, db, ctx, `DELETE FROM auth.role_permissions;
 UPDATE auth.roles SET mfa_required=true WHERE key='requirement_fixture'`)
	read(t, false, false, true)
	accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name) VALUES('other_fixture','Other fixture')`)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='other_fixture'`, user)
	read(t, false, false, true)
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=(SELECT id FROM auth.roles WHERE key='requirement_fixture')`, user)
	read(t, false, false, false)
	accessExec(t, db, ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Administrator',true)`)
	accessExec(t, db, ctx, `INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM auth.roles WHERE key='super_admin'`, user)
	read(t, true, true, false)
	accessExec(t, db, ctx, `DELETE FROM auth.user_roles WHERE user_id=$1`, user)
	read(t, false, false, false)

	accessExec(t, db, ctx, `CREATE ROLE auth_mfa_predicates_runtime LOGIN PASSWORD 'synthetic-recovery-only';
 GRANT USAGE ON SCHEMA auth TO auth_mfa_predicates_runtime`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `DROP OWNED BY auth_mfa_predicates_runtime; DROP ROLE auth_mfa_predicates_runtime`)
	})
	runtime := operatorPool(t, ctx, db, "auth_mfa_predicates_runtime")
	for _, function := range []string{"has_administrative_access", "administrative_mfa_required"} {
		var definer bool
		var volatility string
		require.NoError(t, db.QueryRow(ctx, `SELECT prosecdef,provolatile::text FROM pg_proc WHERE oid=to_regprocedure($1)`, "auth."+function+"(uuid)").Scan(&definer, &volatility))
		require.False(t, definer, "requirement lookup must not elevate SQL privileges")
		require.Equal(t, "s", volatility, "lookup must use the caller statement snapshot")
		var value bool
		err := runtime.QueryRow(ctx, "SELECT auth."+function+"($1)", user).Scan(&value)
		var denied *pgconn.PgError
		require.ErrorAs(t, err, &denied)
		require.Equal(t, "42501", denied.Code, "function must not bypass missing table grants")
	}
}

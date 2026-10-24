package main

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/deploy"
	"github.com/Inforberi/financial-intelligence/migrations"
)

func projectRuntimeProfileDrill(t *testing.T, admin *pgx.Conn, runtime *pgxpool.Pool, attempt func(context.Context) error) {
	t.Helper()
	ctx := t.Context()
	role := pgx.Identifier{runtime.Config().ConnConfig.User}.Sanitize()
	var checksum, realm, project, reservation string
	var version int64
	var owner string
	require.NoError(t, admin.QueryRow(ctx, `SELECT schema_checksum,realm_id::text,project_id::text,reservation_id::text,schema_version
		FROM project_meta.identity WHERE singleton`).Scan(&checksum, &realm, &project, &reservation, &version))
	require.NoError(t, admin.QueryRow(ctx, `SELECT pg_get_userbyid(owner_oid)::text FROM project_meta.identity WHERE singleton`).Scan(&owner))
	require.NoError(t, attempt(ctx), "valid profile must work before fault injection")
	var fields []string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
		WHERE attrelid='auth.project_identity'::regclass AND attnum>0 AND NOT attisdropped`).Scan(&fields))
	require.Equal(t, []string{"realm_id", "project_id", "reservation_id", "database_oid", "owner_oid", "runtime_oid", "schema_version", "schema_checksum"}, fields)
	_, err := admin.Exec(ctx, deploy.RuntimeGrants(runtime.Config().ConnConfig.Database, runtime.Config().ConnConfig.User))
	require.NoError(t, err, "restore/reapply grants must preserve the read-only projection")
	_, err = runtime.Exec(ctx, `SELECT setup_operator_hash FROM project_meta.identity`)
	require.Error(t, err)
	_, err = runtime.Exec(ctx, `SELECT setup_operator_hash FROM auth.project_identity`)
	require.Error(t, err)
	_, err = runtime.Exec(ctx, `UPDATE auth.project_identity SET schema_version=schema_version`)
	require.Error(t, err)
	restoreView := `DROP VIEW auth.project_identity; ` + migrations.ProjectIdentityView +
		` ALTER VIEW auth.project_identity OWNER TO ` + pgx.Identifier{owner}.Sanitize() +
		`; REVOKE ALL ON auth.project_identity FROM :runtime; GRANT SELECT ON auth.project_identity TO :runtime`

	for _, test := range []struct {
		name, change, restore string
		args                  []any
	}{
		{
			"checksum", `UPDATE project_meta.identity SET schema_checksum=repeat('0',64)`,
			`UPDATE project_meta.identity SET schema_checksum=$1`,
			[]any{checksum},
		},
		{
			"schema version", `UPDATE project_meta.identity SET schema_version=schema_version+1`,
			`UPDATE project_meta.identity SET schema_version=$1`,
			[]any{version},
		},
		{
			"realm", `UPDATE project_meta.identity SET realm_id='e2000000-0000-4000-8000-000000000091'`,
			`UPDATE project_meta.identity SET realm_id=$1`,
			[]any{realm},
		},
		{
			"project", `UPDATE project_meta.identity SET project_id='e2000000-0000-4000-8000-000000000091'`,
			`UPDATE project_meta.identity SET project_id=$1`,
			[]any{project},
		},
		{
			"reservation", `UPDATE project_meta.identity SET reservation_id='e2000000-0000-4000-8000-000000000091'`,
			`UPDATE project_meta.identity SET reservation_id=$1`,
			[]any{reservation},
		},
		{
			"view write grant", `GRANT UPDATE ON auth.project_identity TO :runtime`,
			`REVOKE UPDATE ON auth.project_identity FROM :runtime`, nil,
		},
		{
			"missing view read", `REVOKE SELECT ON auth.project_identity FROM :runtime`,
			`GRANT SELECT ON auth.project_identity TO :runtime`, nil,
		},
		{
			"public view", `GRANT SELECT ON auth.project_identity TO PUBLIC`,
			`REVOKE SELECT ON auth.project_identity FROM PUBLIC`, nil,
		},
		{
			"public column", `GRANT SELECT(schema_checksum) ON auth.project_identity TO PUBLIC`,
			`REVOKE SELECT(schema_checksum) ON auth.project_identity FROM PUBLIC`, nil,
		},
		{
			"unexpected private projection", `CREATE OR REPLACE VIEW auth.project_identity AS
			SELECT realm_id,project_id,reservation_id,database_oid,owner_oid,runtime_oid,schema_version,schema_checksum,setup_operator_hash
			FROM project_meta.identity WHERE singleton`, restoreView, nil,
		},
		{
			"private column grant", `GRANT SELECT(setup_operator_hash) ON project_meta.identity TO :runtime`,
			`REVOKE SELECT(setup_operator_hash) ON project_meta.identity FROM :runtime`, nil,
		},
		{
			"missing role permission", `REVOKE UPDATE ON auth.roles FROM :runtime`,
			`GRANT UPDATE ON auth.roles TO :runtime`, nil,
		},
		{"assignment receipt update", `GRANT UPDATE ON auth.platform_role_assignments TO :runtime`, `REVOKE UPDATE ON auth.platform_role_assignments FROM :runtime`, nil},
		{"assignment receipt delete", `GRANT DELETE ON auth.platform_role_assignments TO :runtime`, `REVOKE DELETE ON auth.platform_role_assignments FROM :runtime`, nil},
		{"assignment receipt timestamp", `GRANT INSERT(created_at) ON auth.platform_role_assignments TO :runtime`, `REVOKE INSERT(created_at) ON auth.platform_role_assignments FROM :runtime`, nil},
		{"missing assignment receipt insert", `REVOKE INSERT(changed) ON auth.platform_role_assignments FROM :runtime`, `GRANT INSERT(changed) ON auth.platform_role_assignments TO :runtime`, nil},
		{
			"missing view permission", `REVOKE SELECT ON auth.role_bound_sessions FROM :runtime`,
			`GRANT SELECT ON auth.role_bound_sessions TO :runtime`, nil,
		},
		{
			"missing sequence permission", `REVOKE USAGE ON ALL SEQUENCES IN SCHEMA auth FROM :runtime`,
			`GRANT USAGE ON ALL SEQUENCES IN SCHEMA auth TO :runtime`, nil,
		},
		{
			"DDL privilege", `GRANT CREATE ON SCHEMA auth TO :runtime`,
			`REVOKE CREATE ON SCHEMA auth FROM :runtime`, nil,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := admin.Exec(ctx, strings.ReplaceAll(test.change, ":runtime", role))
			require.NoError(t, err)
			rejected := attempt(ctx)
			_, err = admin.Exec(ctx, strings.ReplaceAll(test.restore, ":runtime", role), test.args...)
			require.NoError(t, err)
			require.Error(t, rejected)
			require.NoError(t, attempt(ctx), "restored profile must work independently of the next case")
			var empty bool
			require.NoError(t, runtime.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.roles)
				AND NOT EXISTS(SELECT 1 FROM auth.platform_role_creations)`).Scan(&empty))
			require.True(t, empty, "profile rejection must happen before role/audit writes")
		})
	}
}

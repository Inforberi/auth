package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectschema "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema"
	authschema "github.com/Inforberi/financial-intelligence/migrations/auth"
)

func (t *Target) recordInstalledSchema(ctx context.Context, tx pgx.Tx, r domain.PreparationReservation, resources Resources, runtime, checksum string) error {
	_, err := tx.Exec(ctx, `CREATE SCHEMA project_meta; REVOKE ALL ON SCHEMA project_meta FROM PUBLIC;
		CREATE TABLE project_meta.identity(
			singleton BOOLEAN PRIMARY KEY CHECK(singleton),realm_id UUID NOT NULL,project_id UUID NOT NULL,
			reservation_id UUID NOT NULL,database_oid OID NOT NULL,owner_oid OID NOT NULL,runtime_oid OID NOT NULL,
			schema_version BIGINT NOT NULL,schema_checksum TEXT NOT NULL,
			configuration_prepared BOOLEAN NOT NULL DEFAULT false,setup_operator_hash TEXT,
			smtp_prepared BOOLEAN NOT NULL DEFAULT false CHECK(NOT smtp_prepared OR configuration_prepared),
			CHECK ((NOT configuration_prepared AND setup_operator_hash IS NULL)
				OR (configuration_prepared AND setup_operator_hash IS NOT NULL AND setup_operator_hash ~ '^[a-f0-9]{64}$')));
		REVOKE ALL ON project_meta.identity FROM PUBLIC`)
	if err != nil {
		return unavailable(ctx)
	}
	role := pgx.Identifier{runtime}.Sanitize()
	if _, err := tx.Exec(ctx, projectschema.ProjectIdentityView+` REVOKE ALL ON auth.project_identity FROM `+role+`; GRANT SELECT ON auth.project_identity TO `+role); err != nil {
		return unavailable(ctx)
	}
	_, err = tx.Exec(ctx, `INSERT INTO project_meta.identity SELECT true,$1,$2,$3,$4,$5,oid,$6,$7 FROM pg_roles WHERE rolname=$8`,
		t.realm, r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, authschema.AuthVersion, checksum, runtime)
	if err != nil {
		return unavailable(ctx)
	}
	return t.checkInstalledSchema(ctx, tx, r, resources, runtime, checksum)
}

func (t *Target) checkInstalledSchema(ctx context.Context, tx pgx.Tx, r domain.PreparationReservation, resources Resources, runtime, checksum string) error {
	var valid bool
	var runtimeOID uint32
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM project_meta.identity marker
		JOIN pg_roles role ON role.oid=marker.runtime_oid
		WHERE marker.singleton AND marker.realm_id=$1 AND marker.project_id=$2 AND marker.reservation_id=$3
		AND marker.database_oid=$4 AND marker.owner_oid=$5 AND marker.schema_version=$6 AND marker.schema_checksum=$7
		AND role.rolname=$8 AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolinherit
		AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role.oid)
		AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
			WHERE m.roleid=role.oid AND member.rolname<>session_user)
		AND NOT has_database_privilege(role.oid,current_database(),'CONNECT,CREATE,TEMP')
		AND has_schema_privilege(role.oid,'auth','USAGE') AND NOT has_schema_privilege(role.oid,'auth','CREATE')
		AND NOT has_schema_privilege(role.oid,'project_meta','USAGE')
		AND NOT has_table_privilege(role.oid,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(role.oid,'auth.platform_role_creations','UPDATE')
		AND NOT has_table_privilege(role.oid,'auth.platform_role_creations','DELETE,TRUNCATE')
		AND NOT has_column_privilege(role.oid,'auth.platform_role_creations','created_at','INSERT')
		AND NOT has_any_column_privilege(role.oid,'auth.platform_role_assignments','UPDATE')
		AND NOT has_any_column_privilege(role.oid,'auth.platform_auth_policy_updates','UPDATE')
		AND NOT has_table_privilege(role.oid,'auth.platform_role_assignments','DELETE,TRUNCATE')
		AND NOT has_table_privilege(role.oid,'auth.platform_auth_policy_updates','DELETE,TRUNCATE')
		AND NOT has_column_privilege(role.oid,'auth.platform_role_assignments','created_at','INSERT')
		AND NOT has_column_privilege(role.oid,'auth.platform_auth_policy_updates','created_at','INSERT')
		AND NOT has_function_privilege(role.oid,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='auth' AND nspowner=$5)
		AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='project_meta' AND nspowner=$5)
		AND EXISTS(SELECT 1 FROM pg_class v JOIN pg_namespace ns ON ns.oid=v.relnamespace
			WHERE ns.nspname='auth' AND v.relname='project_identity' AND v.relkind='v' AND v.relowner=$5
			AND has_table_privilege(role.oid,v.oid,'SELECT')
			AND NOT has_any_column_privilege(role.oid,v.oid,'INSERT,UPDATE,REFERENCES')
			AND NOT has_table_privilege(role.oid,v.oid,'DELETE,TRIGGER,SELECT WITH GRANT OPTION'))
		AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
			CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE')) permission(name)
			WHERE ns.nspname='auth' AND c.relkind IN ('r','p') AND (c.relname<>'restore_audit' OR permission.name='SELECT')
			AND (c.relname<>'platform_role_creations' OR permission.name='SELECT')
			AND (c.relname<>'platform_role_assignments' OR permission.name='SELECT')
			AND (c.relname<>'platform_auth_policy_updates' OR permission.name='SELECT')
			AND (c.relname NOT IN ('platform_user_lifecycle','platform_user_creations','platform_management_audit') OR permission.name='SELECT')
			AND NOT has_table_privilege(role.oid,c.oid,permission.name))
		AND NOT EXISTS(SELECT 1 FROM (VALUES
		  ('auth.platform_user_lifecycle',ARRAY['operation_id','project_id','realm_id','actor_id','user_id','action','expected_version','auth_version','email_id']),
		  ('auth.platform_user_creations',ARRAY['operation_id','project_id','realm_id','actor_id','user_id','fingerprint']),
		  ('auth.platform_management_audit',ARRAY['actor_id','action','target','previous_value','next_value'])
		) AS receipt(name, insert_columns)
		  WHERE has_table_privilege(role.oid,receipt.name,'INSERT,UPDATE,DELETE,TRUNCATE')
		  OR has_any_column_privilege(role.oid,receipt.name,'UPDATE,INSERT WITH GRANT OPTION')
		  OR has_column_privilege(role.oid,receipt.name,'created_at','INSERT')
		  OR EXISTS(SELECT 1 FROM unnest(receipt.insert_columns) col WHERE NOT has_column_privilege(role.oid,receipt.name,col,'INSERT')))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','role_id','role_snapshot','admission_id']) col
			WHERE NOT has_column_privilege(role.oid,'auth.platform_role_creations',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','admission_id','previous_policy','next_policy','changed']) col
			WHERE NOT has_column_privilege(role.oid,'auth.platform_auth_policy_updates',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','user_id','role_id','role_snapshot','access_version','changed','admission_id']) col
			WHERE NOT has_column_privilege(role.oid,'auth.platform_role_assignments',col,'INSERT'))),COALESCE((SELECT runtime_oid FROM project_meta.identity WHERE singleton),0)`,
		t.realm, r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, authschema.AuthVersion, checksum, runtime).Scan(&valid, &runtimeOID)
	if err != nil {
		return unavailable(ctx)
	}
	if !valid {
		return domain.ErrConflict
	}
	t.prepared.runtimeOID = runtimeOID
	return nil
}

func (t *Target) SecretsBinding() (credentials.Binding, error) {
	if t.prepared == nil || !t.prepared.schemaReady || t.prepared.runtimeOID == 0 {
		return credentials.Binding{}, domain.ErrConflict
	}
	r, resources := t.prepared.reservation, t.prepared.resources
	return credentials.Binding{
		RealmID: t.realm, ProjectID: r.ProjectID, ReservationID: r.ReservationID, StorageTarget: t.name,
		DatabaseOID: resources.DatabaseOID, OwnerOID: resources.OwnerOID, RuntimeOID: t.prepared.runtimeOID, SchemaVersion: authschema.AuthVersion,
	}, nil
}

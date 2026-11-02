package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/deploy"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectschema "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema"
	authschema "github.com/Inforberi/financial-intelligence/migrations/auth"
)

const projectRuntimeProfileSQL = `SELECT EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.rolname=session_user
	JOIN pg_roles owner ON owner.oid=d.datdba
	WHERE d.datname=current_database() AND d.datname=$1 AND d.oid=$2 AND d.datdba=$3
	AND NOT d.datistemplate AND d.datallowconn AND d.datacl IS NOT NULL
	AND shobj_description(d.oid,'pg_database')=$4 AND owner.rolname=$5 AND NOT owner.rolcanlogin
	AND r.oid=$6 AND r.rolname=$7 AND current_user=session_user AND r.rolcanlogin
	AND NOT r.rolsuper AND NOT r.rolinherit AND NOT r.rolcreatedb AND NOT r.rolcreaterole
	AND NOT r.rolreplication AND NOT r.rolbypassrls AND r.oid<>d.datdba
	AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid)
	AND has_database_privilege(r.oid,d.oid,'CONNECT') AND NOT has_database_privilege(r.oid,d.oid,'CREATE,TEMP')
	AND NOT has_database_privilege(r.oid,d.oid,'CONNECT WITH GRANT OPTION')
	AND NOT EXISTS(SELECT 1 FROM aclexplode(d.datacl) a WHERE a.grantee NOT IN (d.datdba,r.oid))
	AND has_schema_privilege(r.oid,'auth','USAGE') AND NOT has_schema_privilege(r.oid,'auth','CREATE')
	AND NOT has_schema_privilege(r.oid,'auth','USAGE WITH GRANT OPTION')
	AND NOT has_schema_privilege(r.oid,'public','CREATE') AND NOT has_schema_privilege(r.oid,'project_meta','USAGE,CREATE')
	AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='auth' AND nspowner=$3)
	AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='project_meta' AND nspowner=$3)
	AND EXISTS(SELECT 1 FROM pg_class m JOIN pg_namespace ns ON ns.oid=m.relnamespace
		WHERE ns.nspname='project_meta' AND m.relname='identity' AND m.relkind='r' AND m.relowner=$3
		AND NOT has_any_column_privilege(r.oid,m.oid,'SELECT,INSERT,UPDATE,REFERENCES')
		AND NOT has_table_privilege(r.oid,m.oid,'DELETE,TRUNCATE,TRIGGER'))
	AND EXISTS(SELECT 1 FROM auth.project_identity marker
		WHERE 'auth-project:'||marker.realm_id::text||':'||marker.project_id::text||':'||marker.reservation_id::text=$4
		AND marker.database_oid=$2 AND marker.owner_oid=$3 AND marker.runtime_oid=$6
		AND marker.schema_checksum=$8 AND marker.schema_version=$9)
	AND EXISTS(SELECT 1 FROM pg_class v JOIN pg_namespace ns ON ns.oid=v.relnamespace
		WHERE ns.nspname='auth' AND v.relname='project_identity' AND v.relkind='v' AND v.relowner=$3
		AND (SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
			WHERE attrelid=v.oid AND attnum>0 AND NOT attisdropped)=
			ARRAY['realm_id','project_id','reservation_id','database_oid','owner_oid','runtime_oid','schema_version','schema_checksum']
		AND NOT has_any_column_privilege(r.oid,v.oid,'INSERT,UPDATE,REFERENCES')
		AND NOT has_table_privilege(r.oid,v.oid,'DELETE,TRIGGER,SELECT WITH GRANT OPTION')
		AND NOT EXISTS(SELECT 1 FROM aclexplode(v.relacl) a WHERE a.grantee=0)
		AND NOT EXISTS(SELECT 1 FROM pg_attribute col CROSS JOIN LATERAL aclexplode(col.attacl) a
			WHERE col.attrelid=v.oid AND a.grantee=0))
	AND NOT has_table_privilege(r.oid,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')
	AND NOT has_any_column_privilege(r.oid,'auth.platform_role_creations','UPDATE')
	AND NOT has_table_privilege(r.oid,'auth.platform_role_creations','DELETE,TRUNCATE')
	AND NOT has_column_privilege(r.oid,'auth.platform_role_creations','created_at','INSERT')
	AND NOT has_any_column_privilege(r.oid,'auth.platform_role_assignments','UPDATE')
	AND NOT has_any_column_privilege(r.oid,'auth.platform_auth_policy_updates','UPDATE')
	AND NOT has_table_privilege(r.oid,'auth.platform_role_assignments','DELETE,TRUNCATE')
	AND NOT has_table_privilege(r.oid,'auth.platform_auth_policy_updates','DELETE,TRUNCATE')
	AND NOT has_column_privilege(r.oid,'auth.platform_role_assignments','created_at','INSERT')
	AND NOT has_column_privilege(r.oid,'auth.platform_auth_policy_updates','created_at','INSERT')
	AND NOT has_function_privilege(r.oid,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
	AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
		CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE')) permission(name)
		WHERE ns.nspname='auth' AND c.relkind IN ('r','p','v')
		AND (c.relkind<>'v' OR permission.name='SELECT')
		AND (c.relname<>'restore_audit' OR permission.name='SELECT')
		AND (c.relname<>'platform_role_creations' OR permission.name='SELECT')
		AND (c.relname<>'platform_role_assignments' OR permission.name='SELECT')
		AND (c.relname<>'platform_auth_policy_updates' OR permission.name='SELECT')
		AND (c.relowner<>$3 OR NOT has_table_privilege(r.oid,c.oid,permission.name)
			OR has_table_privilege(r.oid,c.oid,permission.name||' WITH GRANT OPTION')
			OR (permission.name='SELECT' AND has_table_privilege(r.oid,c.oid,'TRUNCATE'))))
	AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
		WHERE ns.nspname='auth' AND c.relkind='S' AND (c.relowner<>$3
			OR NOT has_sequence_privilege(r.oid,c.oid,'USAGE') OR NOT has_sequence_privilege(r.oid,c.oid,'SELECT')
			OR has_sequence_privilege(r.oid,c.oid,'UPDATE,USAGE WITH GRANT OPTION,SELECT WITH GRANT OPTION')))
	AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','role_id','role_snapshot','admission_id']) col
		WHERE NOT has_column_privilege(r.oid,'auth.platform_role_creations',col,'INSERT')
		OR has_column_privilege(r.oid,'auth.platform_role_creations',col,'INSERT WITH GRANT OPTION'))
	AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','admission_id','previous_policy','next_policy','changed']) col
		WHERE NOT has_column_privilege(r.oid,'auth.platform_auth_policy_updates',col,'INSERT')
		OR has_column_privilege(r.oid,'auth.platform_auth_policy_updates',col,'INSERT WITH GRANT OPTION'))
	AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','user_id','role_id','role_snapshot','access_version','changed','admission_id']) col
		WHERE NOT has_column_privilege(r.oid,'auth.platform_role_assignments',col,'INSERT')
		OR has_column_privilege(r.oid,'auth.platform_role_assignments',col,'INSERT WITH GRANT OPTION')))`

func runtimeProfileArguments(b credentials.Binding) ([]any, error) {
	database, owner, err := (domain.PreparationReservation{ProjectID: b.ProjectID, ReservationID: b.ReservationID}).ResourceNames()
	if err != nil || !domain.ValidID(b.RealmID) || !domain.ValidStorageTarget(b.StorageTarget) || b.SchemaVersion != authschema.AuthVersion ||
		b.DatabaseOID == 0 || b.OwnerOID == 0 || b.RuntimeOID == 0 {
		return nil, domain.ErrConflict
	}
	runtime := "authr_" + strings.TrimPrefix(owner, "autho_")
	marker := "auth-project:" + string(b.RealmID) + ":" + string(b.ProjectID) + ":" + string(b.ReservationID)
	return []any{
		database, b.DatabaseOID, b.OwnerOID, marker, owner, b.RuntimeOID, runtime,
		projectschema.ProjectSchemaChecksum(deploy.RuntimeGrants(database, runtime)), b.SchemaVersion,
	}, nil
}

// The check runs on the actual mutation transaction, never on another pool connection.
func CheckRuntime(ctx context.Context, tx pgx.Tx, binding credentials.Binding) error {
	args, err := runtimeProfileArguments(binding)
	if err != nil {
		return err
	}
	var safe bool
	if err := tx.QueryRow(ctx, projectRuntimeProfileSQL, args...).Scan(&safe); err != nil {
		return sqlerrors.Catalog(ctx, err)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}

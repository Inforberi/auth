package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

func (t *Target) recordInstalledSchema(ctx context.Context, tx pgx.Tx, r domain.PreparationReservation, resources Resources, runtime, checksum string) error {
	_, err := tx.Exec(ctx, `CREATE SCHEMA project_meta; REVOKE ALL ON SCHEMA project_meta FROM PUBLIC;
		CREATE TABLE project_meta.identity(
			singleton BOOLEAN PRIMARY KEY CHECK(singleton),realm_id UUID NOT NULL,project_id UUID NOT NULL,
			reservation_id UUID NOT NULL,database_oid OID NOT NULL,owner_oid OID NOT NULL,runtime_oid OID NOT NULL,
			schema_version BIGINT NOT NULL,schema_checksum TEXT NOT NULL);
		REVOKE ALL ON project_meta.identity FROM PUBLIC`)
	if err != nil {
		return unavailable(ctx)
	}
	_, err = tx.Exec(ctx, `INSERT INTO project_meta.identity SELECT true,$1,$2,$3,$4,$5,oid,$6,$7 FROM pg_roles WHERE rolname=$8`,
		t.realm, r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, migrations.AuthVersion, checksum, runtime)
	if err != nil {
		return unavailable(ctx)
	}
	return t.checkInstalledSchema(ctx, tx, r, resources, runtime, checksum)
}

func (t *Target) checkInstalledSchema(ctx context.Context, tx pgx.Tx, r domain.PreparationReservation, resources Resources, runtime, checksum string) error {
	var valid bool
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
		AND NOT has_function_privilege(role.oid,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='auth' AND nspowner=$5)
		AND EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='project_meta' AND nspowner=$5)
		AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
			CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE')) permission(name)
			WHERE ns.nspname='auth' AND c.relkind IN ('r','p') AND (c.relname<>'restore_audit' OR permission.name='SELECT')
			AND NOT has_table_privilege(role.oid,c.oid,permission.name)))`,
		t.realm, r.ProjectID, r.ReservationID, resources.DatabaseOID, resources.OwnerOID, migrations.AuthVersion, checksum, runtime).Scan(&valid)
	if err != nil {
		return unavailable(ctx)
	}
	if !valid {
		return domain.ErrConflict
	}
	return nil
}

package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/migrations"
)

// CheckOnboardingRuntime is a read-only cold-open probe, not authority to activate a database.
func CheckOnboardingRuntime(ctx context.Context, db *pgxpool.Pool, proof credentials.SetupProof) error {
	b := proof.Binding()
	database, owner, err := (domain.PreparationReservation{ProjectID: b.ProjectID, ReservationID: b.ReservationID}).ResourceNames()
	if err != nil || db == nil || proof.Digest() == "" || b.SchemaVersion != migrations.AuthVersion {
		return domain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	runtime := "authr_" + strings.TrimPrefix(owner, "autho_")
	marker := "auth-project:" + string(b.RealmID) + ":" + string(b.ProjectID) + ":" + string(b.ReservationID)
	var safe bool
	err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON r.rolname=session_user
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
		AND NOT has_table_privilege(r.oid,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(r.oid,'auth.platform_role_creations','UPDATE')
		AND NOT has_table_privilege(r.oid,'auth.platform_role_creations','DELETE,TRUNCATE')
		AND NOT has_column_privilege(r.oid,'auth.platform_role_creations','created_at','INSERT')
		AND NOT has_function_privilege(r.oid,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
			CROSS JOIN (VALUES('SELECT'),('INSERT'),('UPDATE'),('DELETE')) permission(name)
			WHERE ns.nspname='auth' AND c.relkind IN ('r','p')
			AND (c.relname<>'restore_audit' OR permission.name='SELECT')
			AND (c.relname<>'platform_role_creations' OR permission.name='SELECT')
			AND (c.relowner<>$3 OR NOT has_table_privilege(r.oid,c.oid,permission.name)
				OR has_table_privilege(r.oid,c.oid,permission.name||' WITH GRANT OPTION')
				OR (permission.name='SELECT' AND has_table_privilege(r.oid,c.oid,'TRUNCATE'))))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','realm_id','actor_id','project_id','binding','request','role_id','role_snapshot','admission_id']) col
			WHERE NOT has_column_privilege(r.oid,'auth.platform_role_creations',col,'INSERT')
			OR has_column_privilege(r.oid,'auth.platform_role_creations',col,'INSERT WITH GRANT OPTION'))
		AND EXISTS(SELECT 1 FROM auth.initial_setup WHERE singleton AND operator_hash=$8 AND initialized_at IS NULL)
		AND EXISTS(SELECT 1 FROM auth.auth_settings WHERE singleton AND version=1 AND password_enabled
			AND NOT(registration_enabled OR email_otp_enabled OR google_enabled OR telegram_enabled
			OR google_registration_enabled OR telegram_registration_enabled OR token_session_exchange_enabled OR token_native_enabled)
			AND password_email_verification='disabled'))`,
		database, b.DatabaseOID, b.OwnerOID, marker, owner, b.RuntimeOID, runtime, proof.Digest()).Scan(&safe)
	if err != nil {
		return catalogError(ctx, err)
	}
	if !safe {
		return domain.ErrConflict
	}
	return nil
}

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

// CheckRuntime rejects a project database, privileged connection and incomplete grants before assembly writes.
func (r *Repository) CheckRuntime(ctx context.Context, setupEnabled bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ready bool
	err := r.db.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1 AND (initialized_at IS NOT NULL OR $2))
		AND current_user=session_user
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname IN ('auth_recovery_operator','auth_mfa_recovery_operator')
			AND pg_has_role(session_user,g.oid,'MEMBER'))
		AND NOT has_function_privilege(current_user,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
			AND (role.rolname=current_user OR pg_has_role(current_user,role.oid,'MEMBER')))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database db WHERE db.datname=current_database() AND pg_has_role(current_user,db.datdba,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace ns WHERE ns.nspname IN ('auth','platform') AND pg_has_role(current_user,ns.nspowner,'MEMBER'))
		AND NOT has_database_privilege(current_user,current_database(),'CREATE')
		AND NOT has_schema_privilege(current_user,'auth','CREATE')
		AND NOT has_schema_privilege(current_user,'platform','CREATE')
		AND NOT has_schema_privilege(current_user,'public','CREATE')
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
			WHERE ns.nspname IN ('auth','platform') AND c.relkind IN ('r','p','v','S') AND pg_has_role(current_user,c.relowner,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM (VALUES
			('platform.projects','SELECT'),
			('platform.project_events','SELECT'),
			('platform.project_creations','SELECT'),('platform.project_creations','INSERT'),
			('platform.project_role_intents','SELECT'),
			('platform.project_role_admissions','SELECT'),('platform.project_role_outcomes','SELECT'),
			('platform.operator_realm','SELECT'),('platform.operator_permissions','SELECT'),('platform.operator_permissions','INSERT'),
			('platform.operator_audit','SELECT'),('platform.operator_audit','INSERT')) required(relation,privilege)
			WHERE NOT has_table_privilege(current_user,required.relation,required.privilege))
		AND has_column_privilege(current_user,'platform.operator_realm','initialized_at','UPDATE')
		AND has_column_privilege(current_user,'platform.operator_realm','first_operator_id','UPDATE')
		AND has_column_privilege(current_user,'platform.operator_permissions','permission_key','UPDATE')
		AND NOT has_column_privilege(current_user,'platform.operator_permissions','user_id','UPDATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['desired_state','phase','version','generation','updated_at']) col
			WHERE NOT has_column_privilege(current_user,'platform.projects',col,'UPDATE'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['id','slug','name','origin','storage_target','database_name','credential_ref','schema_version','created_at']) col
			WHERE has_column_privilege(current_user,'platform.projects',col,'UPDATE'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','operation_id','action','actor_kind','actor_id','reason',
			'from_state','from_phase','from_version','from_generation','to_state','to_phase','to_version','to_generation']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_events',col,'INSERT'))
		AND NOT has_column_privilege(current_user,'platform.project_events','created_at','INSERT')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['id','slug','name','origin','storage_target']) col
			WHERE NOT has_column_privilege(current_user,'platform.projects',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['desired_state','phase','version','generation','database_name','credential_ref','schema_version','created_at','updated_at']) col
			WHERE has_column_privilege(current_user,'platform.projects',col,'INSERT'))
		AND NOT has_table_privilege(current_user,'platform.projects','INSERT,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.project_creations','UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.project_role_intents','DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'platform.project_role_intents','UPDATE,REFERENCES')
		AND NOT has_column_privilege(current_user,'platform.project_role_intents','created_at','INSERT')
		AND NOT has_table_privilege(current_user,'platform.project_role_admissions','UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'platform.project_role_admissions','UPDATE,REFERENCES')
		AND NOT has_column_privilege(current_user,'platform.project_role_admissions','admission_id','INSERT')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','created_at','expires_at']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_role_admissions',col,'INSERT'))
		AND NOT has_table_privilege(current_user,'platform.project_role_outcomes','UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'platform.project_role_outcomes','UPDATE,REFERENCES')
		AND NOT has_column_privilege(current_user,'platform.project_role_outcomes','created_at','INSERT')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','admission_id','role_snapshot']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_role_outcomes',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','project_id','realm_id','actor_id','version','generation','binding','request']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_role_intents',col,'INSERT'))
		AND NOT has_table_privilege(current_user,'platform.project_preparations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.project_secrets','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'platform.project_secrets','INSERT,UPDATE,REFERENCES')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['ciphertext','key_id','format_version','created_at']) col
			WHERE has_column_privilege(current_user,'platform.project_secrets',col,'SELECT'))
		AND NOT has_column_privilege(current_user,'platform.project_preparations','onboarding_admitted','INSERT,UPDATE')
		AND NOT has_column_privilege(current_user,'platform.project_preparations','secrets_created','INSERT,UPDATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','reservation_id','storage_target','operation_id','version','generation','created_at']) col
			WHERE has_column_privilege(current_user,'platform.project_preparations',col,'INSERT,UPDATE'))
		AND NOT has_table_privilege(current_user,'platform.project_events','UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.operator_realm','INSERT,DELETE,TRUNCATE')
		AND NOT has_column_privilege(current_user,'platform.operator_realm','id','UPDATE')
		AND NOT has_table_privilege(current_user,'platform.operator_audit','UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'auth.platform_role_creations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'auth.platform_role_creations','SELECT,INSERT,UPDATE,REFERENCES')
		AND NOT has_table_privilege(current_user,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')`, r.realm, setupEnabled).Scan(&ready)
	if err != nil {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	if !ready {
		return domain.ErrUnavailable
	}
	return nil
}

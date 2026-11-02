package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

type PreparationRepository struct {
	db     *pgxpool.Pool
	realm  domain.ID
	target string
}

func NewPreparation(db *pgxpool.Pool, realm domain.ID, target string) (*PreparationRepository, error) {
	if db == nil || !domain.ValidID(realm) || !domain.ValidStorageTarget(target) {
		return nil, domain.ErrUnavailable
	}
	return &PreparationRepository{db: db, realm: realm, target: target}, nil
}

// CheckRuntime is for the catalog credential, not the future privileged storage connection.
func (r *PreparationRepository) CheckRuntime(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var allowed bool
	err := r.db.QueryRow(ctx, `SELECT current_user=session_user
		AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL)
		AND NOT EXISTS(SELECT 1 FROM pg_roles role WHERE (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolreplication OR role.rolbypassrls)
			AND (role.rolname=current_user OR pg_has_role(current_user,role.oid,'MEMBER')))
		AND NOT EXISTS(SELECT 1 FROM pg_database db WHERE db.datname=current_database() AND pg_has_role(current_user,db.datdba,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_namespace ns WHERE ns.nspname IN ('auth','platform') AND pg_has_role(current_user,ns.nspowner,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace
			WHERE ns.nspname IN ('auth','platform') AND c.relkind IN ('r','p','v','S') AND pg_has_role(current_user,c.relowner,'MEMBER'))
		AND NOT has_database_privilege(current_user,current_database(),'CREATE')
		AND NOT has_schema_privilege(current_user,'auth','USAGE')
		AND NOT has_schema_privilege(current_user,'platform','CREATE')
		AND NOT has_schema_privilege(current_user,'public','CREATE')
		AND NOT has_table_privilege(current_user,'platform.operator_permissions','INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.operator_realm','INSERT,UPDATE,DELETE,TRUNCATE')
		AND has_column_privilege(current_user,'platform.operator_realm','singleton','UPDATE')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['id','initialized_at','first_operator_id']) col
			WHERE has_column_privilege(current_user,'platform.operator_realm',col,'UPDATE'))
		AND NOT has_table_privilege(current_user,'platform.project_creations','INSERT,UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.project_events','UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.projects','INSERT,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'platform.project_preparations','DELETE,TRUNCATE')
		AND has_table_privilege(current_user,'platform.project_secrets','SELECT')
		AND NOT has_any_column_privilege(current_user,'platform.project_secrets','UPDATE,REFERENCES')
		AND NOT has_table_privilege(current_user,'platform.project_secrets','DELETE,TRUNCATE')
		AND NOT has_column_privilege(current_user,'platform.project_secrets','created_at','INSERT')
		AND has_column_privilege(current_user,'platform.project_preparations','secrets_created','UPDATE')
		AND has_column_privilege(current_user,'platform.project_preparations','onboarding_admitted','UPDATE')
		AND NOT has_column_privilege(current_user,'platform.project_preparations','onboarding_admitted','INSERT')
		AND NOT has_column_privilege(current_user,'platform.project_preparations','secrets_created','INSERT')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','reservation_id','storage_target','database_oid','owner_oid','runtime_oid',
			'schema_version','format_version','key_id','ciphertext']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_secrets',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM (VALUES
			('platform.operator_realm','SELECT'),('platform.projects','SELECT'),('platform.project_events','SELECT'),
			('platform.project_preparations','SELECT')) required(relation,privilege)
			WHERE NOT has_table_privilege(current_user,required.relation,required.privilege))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['desired_state','phase','version','generation','updated_at']) col
			WHERE NOT has_column_privilege(current_user,'platform.projects',col,'UPDATE'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['id','slug','name','origin','storage_target','database_name','credential_ref','schema_version','created_at']) col
			WHERE has_column_privilege(current_user,'platform.projects',col,'UPDATE'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','operation_id','action','actor_kind','actor_id','reason',
			'from_state','from_phase','from_version','from_generation','to_state','to_phase','to_version','to_generation']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_events',col,'INSERT'))
		AND NOT has_column_privilege(current_user,'platform.project_events','created_at','INSERT')
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','storage_target','operation_id','version','generation']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_preparations',col,'INSERT'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['operation_id','version','generation']) col
			WHERE NOT has_column_privilege(current_user,'platform.project_preparations',col,'UPDATE'))
		AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['project_id','reservation_id','storage_target','created_at']) col
			WHERE has_column_privilege(current_user,'platform.project_preparations',col,'UPDATE'))
		AND NOT has_column_privilege(current_user,'platform.project_preparations','reservation_id','INSERT')
		AND NOT has_column_privilege(current_user,'platform.project_preparations','created_at','INSERT')`, r.realm).Scan(&allowed)
	if err != nil {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	if !allowed {
		return domain.ErrUnavailable
	}
	return nil
}

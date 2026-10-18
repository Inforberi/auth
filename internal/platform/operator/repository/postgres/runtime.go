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
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolbypassrls)
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
			('platform.operator_realm','SELECT'),('platform.operator_permissions','SELECT'),('platform.operator_permissions','INSERT'),
			('platform.operator_audit','SELECT'),('platform.operator_audit','INSERT')) required(relation,privilege)
			WHERE NOT has_table_privilege(current_user,required.relation,required.privilege))
		AND has_column_privilege(current_user,'platform.operator_realm','initialized_at','UPDATE')
		AND has_column_privilege(current_user,'platform.operator_realm','first_operator_id','UPDATE')
		AND NOT has_table_privilege(current_user,'platform.operator_realm','INSERT,DELETE,TRUNCATE')
		AND NOT has_column_privilege(current_user,'platform.operator_realm','id','UPDATE')
		AND NOT has_table_privilege(current_user,'platform.operator_audit','UPDATE,DELETE,TRUNCATE')
		AND NOT has_table_privilege(current_user,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')`, r.realm, setupEnabled).Scan(&ready)
	if err != nil {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	if !ready {
		return domain.ErrUnavailable
	}
	return nil
}

package postgres

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

// CheckRecovery is an offline connection admission check, not a replacement for Auth transaction guards.
func (r *Repository) CheckRecovery(ctx context.Context, user accountdomain.UserID, mfa bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	group, other := "platform_password_recovery_operator", "auth_mfa_recovery_operator"
	if mfa {
		group, other = "platform_mfa_recovery_operator", "auth_recovery_operator"
	}
	var ready bool
	err := r.db.QueryRow(ctx, `SELECT current_user=session_user
		AND EXISTS(SELECT 1 FROM platform.operator_realm WHERE id=$1 AND initialized_at IS NOT NULL)
		AND EXISTS(SELECT 1 FROM platform.operator_permissions WHERE user_id=$2)
		AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname=$3 AND NOT g.rolcanlogin
			AND pg_has_role(session_user,g.oid,'MEMBER'))
		AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles base WHERE base.rolname=CASE WHEN $5 THEN 'auth_mfa_recovery_operator' ELSE 'auth_recovery_operator' END
			AND NOT base.rolcanlogin AND pg_has_role(session_user,base.oid,'MEMBER')
			AND NOT pg_has_role(session_user,base.oid,'USAGE') AND NOT pg_has_role(session_user,base.oid,'SET'))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles g WHERE g.rolname=$4 AND pg_has_role(session_user,g.oid,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE (role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR role.rolbypassrls)
			AND (role.rolname=current_user OR pg_has_role(current_user,role.oid,'MEMBER')))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database db WHERE db.datname=current_database() AND pg_has_role(current_user,db.datdba,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace ns WHERE ns.nspname IN ('auth','platform') AND pg_has_role(current_user,ns.nspowner,'MEMBER'))
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
			WHERE ns.nspname IN ('auth','platform') AND c.relkind IN ('r','p','v','S') AND pg_has_role(current_user,c.relowner,'MEMBER'))
		AND NOT has_database_privilege(current_user,current_database(),'CREATE')
		AND NOT has_schema_privilege(current_user,'auth','CREATE')
		AND NOT has_schema_privilege(current_user,'platform','CREATE')
		AND NOT has_schema_privilege(current_user,'public','CREATE')
		AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace ns ON ns.oid=c.relnamespace
			WHERE ns.nspname='platform' AND c.relkind IN ('r','p') AND
			(has_table_privilege(current_user,c.oid,'INSERT,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,c.oid,'UPDATE')))
		AND NOT has_any_column_privilege(current_user,'auth.mfa_totp','SELECT,INSERT,UPDATE')
		AND NOT has_table_privilege(current_user,'auth.mfa_totp','DELETE,TRUNCATE')
		AND NOT has_any_column_privilege(current_user,'auth.mfa_recovery_requests','UPDATE')
		AND NOT has_any_column_privilege(current_user,'auth.initial_setup','UPDATE')
		AND NOT has_table_privilege(current_user,'auth.restore_audit','INSERT,UPDATE,DELETE,TRUNCATE')
		AND CASE WHEN $5 THEN
			NOT has_column_privilege(current_user,'auth.password_credentials','password_hash','SELECT,UPDATE')
			AND has_function_privilege(current_user,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE')
		ELSE NOT has_function_privilege(current_user,'auth.decide_mfa_recovery(uuid,uuid,bigint,boolean,text,text)','EXECUTE') END`,
		r.realm, user, group, other, mfa).Scan(&ready)
	if err != nil || !ready {
		return errors.Join(domain.ErrUnavailable, ctx.Err())
	}
	return nil
}

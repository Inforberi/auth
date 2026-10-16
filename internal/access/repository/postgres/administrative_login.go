package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

// The caller holds Access then user locks. Enrolled factor checks/consumption remain with the MFA caller.
func AdministrativePasswordAllowed(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, hash string) (bool, error) {
	keys := []string{
		string(settings.RolesManage), string(settings.AssignmentsManage), string(settings.EmailBindingManage),
		string(settings.UsersManage), string(settings.UsersRead), string(settings.UsersStatusManage), string(settings.UsersDelete), string(settings.AuthSettingsManage),
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.password_credentials p
		JOIN auth.user_emails e ON e.id=p.email_id AND e.user_id=p.user_id
		WHERE p.user_id=$1 AND p.password_hash=$2 AND e.verified_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM auth.temporary_password_credentials WHERE user_id=$1)
		AND NOT EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=$1 AND (activated_at IS NULL OR password_change_required))
		AND EXISTS(SELECT 1 FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
			WHERE ur.user_id=$1 AND (r.system AND r.key='super_admin' OR EXISTS(
				SELECT 1 FROM auth.role_permissions rp WHERE rp.role_id=r.id AND rp.permission_key=ANY($3::text[])))))`, user, hash, keys).Scan(&allowed)
	return allowed, err
}

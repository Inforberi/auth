package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
)

func (r *Repository) HasPermission(ctx context.Context, principal service.Principal, permission domain.PermissionKey) (bool, error) {
	var allowed bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM auth.role_bound_sessions s
		JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
		WHERE s.user_id=$1 AND s.token_hash=$2 AND s.revoked_at IS NULL
		AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()
		AND u.status='active' AND u.deleted_at IS NULL
		AND EXISTS (
			SELECT 1 FROM auth.user_roles ur
			JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=u.id AND rp.permission_key=$3
		)
	)`, principal.UserID, principal.TokenHash, permission).Scan(&allowed)
	return allowed, err
}

package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
)

func (r *Repository) ReadAccess(ctx context.Context, principal service.Principal, known []domain.PermissionKey) (domain.UserAccess, error) {
	keys := make([]string, 0, len(known))
	for _, key := range known {
		keys = append(keys, string(key))
	}
	var access domain.UserAccess
	err := r.db.QueryRow(ctx, `SELECT u.access_version,
		ARRAY(SELECT role_id FROM auth.user_roles WHERE user_id=u.id ORDER BY role_id LIMIT 33),
		ARRAY(SELECT DISTINCT rp.permission_key FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=u.id AND rp.permission_key=ANY($3::text[]) ORDER BY rp.permission_key)
		FROM auth.users u JOIN auth.sessions s ON s.user_id=u.id AND s.auth_version=u.auth_version
		WHERE u.id=$1 AND s.token_hash=$2 AND u.status='active' AND u.deleted_at IS NULL
		AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()`,
		principal.UserID, principal.TokenHash, keys).Scan(&access.Version, &access.RoleIDs, &access.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserAccess{}, domain.ErrForbidden
	}
	if err != nil {
		return domain.UserAccess{}, err
	}
	if len(access.RoleIDs) > domain.MaxUserRoles {
		return domain.UserAccess{}, domain.ErrConflict
	}
	return access, nil
}

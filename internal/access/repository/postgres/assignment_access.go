package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *Repository) ReadAssignments(ctx context.Context, actor service.Principal, target accountdomain.UserID, known []domain.PermissionKey) (domain.UserAccess, error) {
	keys := make([]string, 0, len(known))
	for _, key := range known {
		keys = append(keys, string(key))
	}
	var access domain.UserAccess
	err := r.db.QueryRow(ctx, `SELECT target.access_version,
		ARRAY(SELECT role_id FROM auth.user_roles WHERE user_id=target.id ORDER BY role_id LIMIT 33),
		ARRAY(SELECT DISTINCT rp.permission_key FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
			WHERE ur.user_id=target.id AND rp.permission_key=ANY($4::text[]) ORDER BY rp.permission_key)
		FROM auth.users target
		WHERE target.id=$3 AND target.deleted_at IS NULL AND EXISTS (
			SELECT 1 FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id AND u.auth_version=s.auth_version
			WHERE u.id=$1 AND s.token_hash=$2 AND u.status='active' AND u.deleted_at IS NULL
			AND s.revoked_at IS NULL AND s.expires_at>statement_timestamp() AND s.absolute_expires_at>statement_timestamp()
			AND EXISTS (SELECT 1 FROM auth.user_roles ur JOIN auth.role_permissions rp ON rp.role_id=ur.role_id
				WHERE ur.user_id=u.id AND rp.permission_key=$5)
		)`, actor.UserID, actor.TokenHash, target, keys, settings.AssignmentsManage).Scan(&access.Version, &access.RoleIDs, &access.Permissions)
	// Do not distinguish an unknown target from a missing administrative permission.
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

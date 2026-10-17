package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func (r *Repository) ReadRole(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	return readRole(ctx, r.db, id)
}

type roleReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readRole(ctx context.Context, db roleReader, id domain.RoleID) (domain.Role, error) {
	var role domain.Role
	err := db.QueryRow(ctx, `SELECT r.id,r.key,r.name,r.description,r.system,r.version,r.mfa_required,
		ARRAY(SELECT permission_key FROM auth.role_permissions WHERE role_id=r.id ORDER BY permission_key)
		FROM auth.roles r WHERE r.id=$1`, id).Scan(
		&role.ID, &role.Key, &role.Name, &role.Description, &role.System, &role.Version, &role.MFARequired, &role.Permissions,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Role{}, domain.ErrRoleNotFound
	}
	return role, err
}

func (r *Repository) ListRoles(ctx context.Context, afterKey string, limit int) ([]domain.Role, error) {
	rows, err := r.db.Query(ctx, `SELECT id,key,name,description,system,version,mfa_required
		FROM auth.roles WHERE key>$1 ORDER BY key LIMIT $2`, afterKey, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Role, 0, limit)
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.ID, &role.Key, &role.Name, &role.Description, &role.System, &role.Version, &role.MFARequired); err != nil {
			return nil, err
		}
		result = append(result, role)
	}
	return result, rows.Err()
}

package postgres

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func (r *Repository) CreateRole(ctx context.Context, input service.CreateRoleInput) (domain.Role, error) {
	var role domain.Role
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := requireActor(ctx, tx, input.Actor, ""); err != nil {
			return err
		}
		if err := requireDelegation(ctx, tx, input.Actor, settings.RolesManage, input.Permissions); err != nil {
			return err
		}
		role = domain.Role{Key: input.Key, Name: input.Name, Description: input.Description, Version: 1, Permissions: slices.Clone(input.Permissions)}
		if err := tx.QueryRow(ctx, `INSERT INTO auth.roles(key,name,description) VALUES ($1,$2,$3) RETURNING id`, role.Key, role.Name, role.Description).Scan(&role.ID); err != nil {
			return err
		}
		if err := replacePermissions(ctx, tx, role); err != nil {
			return err
		}
		return recordAudit(ctx, tx, input.Actor, role, "role_created", "", nil)
	})
	if err != nil {
		return domain.Role{}, err
	}
	return role, nil
}

func (r *Repository) UpdateRole(ctx context.Context, input service.UpdateRoleInput) (domain.Role, error) {
	var role domain.Role
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := requireActor(ctx, tx, input.Actor, ""); err != nil {
			return err
		}
		current, err := readRole(ctx, tx, input.RoleID)
		if err != nil {
			return err
		}
		if current.System {
			return domain.ErrForbidden
		}
		if current.Version != input.ExpectedVersion {
			return domain.ErrConflict
		}
		permissions := append(slices.Clone(current.Permissions), input.Permissions...)
		if err := requireDelegation(ctx, tx, input.Actor, settings.RolesManage, permissions); err != nil {
			return err
		}
		role = current
		requested := slices.Clone(input.Permissions)
		slices.Sort(requested)
		if current.Key == input.Key && current.Name == input.Name && current.Description == input.Description && slices.Equal(current.Permissions, requested) {
			return nil
		}
		role.Key, role.Name, role.Description, role.Permissions = input.Key, input.Name, input.Description, requested
		elevated := slices.ContainsFunc(requested, func(key domain.PermissionKey) bool {
			return !slices.Contains(current.Permissions, key)
		})
		if err := tx.QueryRow(ctx, `UPDATE auth.roles SET key=$2,name=$3,description=$4,version=version+1,
			session_revision=session_revision+CASE WHEN $5 THEN 1 ELSE 0 END WHERE id=$1 RETURNING version`, role.ID, role.Key, role.Name, role.Description, elevated).Scan(&role.Version); err != nil {
			return err
		}
		if err := replacePermissions(ctx, tx, role); err != nil {
			return err
		}
		return recordAudit(ctx, tx, input.Actor, role, "role_updated", "", nil)
	})
	if err != nil {
		return domain.Role{}, err
	}
	return role, nil
}

func replacePermissions(ctx context.Context, tx pgx.Tx, role domain.Role) error {
	if _, err := tx.Exec(ctx, `DELETE FROM auth.role_permissions WHERE role_id=$1`, role.ID); err != nil {
		return err
	}
	keys := make([]string, 0, len(role.Permissions))
	for _, key := range role.Permissions {
		keys = append(keys, string(key))
	}
	_, err := tx.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[])`, role.ID, keys)
	return err
}

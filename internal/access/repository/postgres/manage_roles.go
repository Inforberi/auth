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
		role.MFARequired = input.MFARequired != nil && *input.MFARequired
		if role.MFARequired && !r.mfaReady {
			return domain.ErrMFANotReady
		}
		var err error
		role, err = InsertRoleInTransaction(ctx, tx, role)
		if err != nil {
			return err
		}
		return recordAudit(ctx, tx, input.Actor, role, "role_created", "", nil)
	})
	if err != nil {
		return domain.Role{}, err
	}
	return role, nil
}

// InsertRoleInTransaction owns only persistence; the caller owns validation,
// authority, Access locking, audit and commit. It must not be called by HTTP.
func InsertRoleInTransaction(ctx context.Context, tx pgx.Tx, role domain.Role) (domain.Role, error) {
	role.Version, role.System = 1, false
	if err := tx.QueryRow(ctx, `INSERT INTO auth.roles(key,name,description,mfa_required) VALUES ($1,$2,$3,$4) RETURNING id`,
		role.Key, role.Name, role.Description, role.MFARequired).Scan(&role.ID); err != nil {
		return domain.Role{}, mapConflict(err)
	}
	if err := replacePermissions(ctx, tx, role); err != nil {
		return domain.Role{}, mapConflict(err)
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
		var changed, elevated bool
		role, changed, elevated, err = (domain.RoleChange{
			Key: input.Key, Name: input.Name, Description: input.Description,
			Permissions: input.Permissions, MFARequired: input.MFARequired,
		}).Apply(current, r.mfaReady)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if err := tx.QueryRow(ctx, `UPDATE auth.roles SET key=$2,name=$3,description=$4,version=version+1,mfa_required=$6,
			session_revision=session_revision+CASE WHEN $5 THEN 1 ELSE 0 END WHERE id=$1 RETURNING version`, role.ID, role.Key, role.Name, role.Description, elevated, role.MFARequired).Scan(&role.Version); err != nil {
			return err
		}
		if err := updateRolePermissions(ctx, tx, current, role); err != nil {
			return err
		}
		return recordAudit(ctx, tx, input.Actor, role, "role_updated", "", nil)
	})
	if err != nil {
		return domain.Role{}, err
	}
	return role, nil
}

func updateRolePermissions(ctx context.Context, tx pgx.Tx, current, updated domain.Role) error {
	if slices.Equal(current.Permissions, updated.Permissions) {
		return nil
	}
	if err := replacePermissions(ctx, tx, updated); err != nil {
		return err
	}
	return requireRoleNonTOTPAdministrativeFactor(ctx, tx, updated.ID)
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

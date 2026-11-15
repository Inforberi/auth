package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	access "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/managementaudit"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *RuntimeRoles) EditRole(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, id access.RoleID, expected int64, change access.RoleChange) (access.Role, error) {
	if !domain.ValidID(domain.ID(id)) || expected < 1 {
		return access.Role{}, access.ErrInvalidRole
	}
	if err := access.ValidateRole(change.Key, change.Name, change.Description, change.Permissions); err != nil {
		return access.Role{}, err
	}
	ready, err := r.projectMFAReady(ctx, actor, target, operators.AccessManage)
	if err != nil {
		return access.Role{}, err
	}
	var result access.Role
	err = r.WriteProject(ctx, actor, target, r.registry, operators.AccessManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		current, err := accesspg.ReadRoleInTransaction(ctx, tx, id)
		if err != nil {
			if errors.Is(err, access.ErrRoleNotFound) {
				return err
			}
			return sqlerrors.Catalog(ctx, err)
		}
		if current.System {
			return access.ErrForbidden
		}
		if current.Version != expected {
			return access.ErrConflict
		}
		for _, permission := range change.Permissions {
			if !r.permissions.Contains(permission) {
				return access.ErrInvalidPermission
			}
		}
		next, changed, elevated, err := change.Apply(current, ready)
		if err != nil {
			return err
		}
		result = next
		if !changed {
			return nil
		}
		if result.MFARequired {
			if _, err := settingspg.ReadMFAPolicyInTransaction(ctx, tx); err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
		}
		result, err = accesspg.SaveRoleChange(ctx, tx, current, next, elevated)
		if err != nil {
			if errors.Is(err, access.ErrConflict) || errors.Is(err, access.ErrMFANotReady) {
				return err
			}
			return sqlerrors.Catalog(ctx, err)
		}
		return sqlerrors.Catalog(ctx, managementaudit.Record(ctx, tx, actor.UserID, "role_updated", string(id), current, result))
	})
	return result, err
}

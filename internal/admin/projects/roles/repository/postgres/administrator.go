package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	access "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/managementaudit"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *RuntimeRoles) ChangeProjectAdministrator(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input accessservice.AdministratorInput) (int64, error) {
	if !account.ValidUserID(input.UserID) || input.ExpectedRoleVersion < 1 || input.ExpectedAccessVersion < 1 || input.ExpectedAuthVersion < 1 {
		return 0, access.ErrInvalidRole
	}
	if input.Grant {
		ready, err := r.projectMFAReady(ctx, actor, target, operators.OperatorsManage)
		if err != nil {
			return 0, err
		}
		if !ready {
			return 0, access.ErrMFANotReady
		}
	}
	var result int64
	err := r.WriteProject(ctx, actor, target, r.registry, operators.OperatorsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var roleID access.RoleID
		if err := tx.QueryRow(ctx, `SELECT id FROM auth.roles WHERE key='super_admin' AND system`).Scan(&roleID); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		role, err := accesspg.ReadRoleInTransaction(ctx, tx, roleID)
		if err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		version, err := accesspg.CheckAdministratorTarget(ctx, tx, input, role)
		if err != nil {
			if errors.Is(err, access.ErrConflict) || errors.Is(err, access.ErrTargetUnavailable) || errors.Is(err, account.ErrLastAdministrator) {
				return err
			}
			return sqlerrors.Catalog(ctx, err)
		}
		var changed bool
		result, changed, err = accesspg.ApplyAssignmentInTransaction(ctx, tx, input.UserID, role.ID, input.Grant, version)
		if err != nil {
			if errors.Is(err, access.ErrConflict) || errors.Is(err, access.ErrMFANotReady) {
				return err
			}
			return sqlerrors.Catalog(ctx, err)
		}
		if !changed {
			return nil
		}
		action := "administrator_revoked"
		if input.Grant {
			action = "administrator_granted"
		}
		return sqlerrors.Catalog(ctx, managementaudit.Record(ctx, tx, actor.UserID, action, string(input.UserID), version, result))
	})
	return result, err
}

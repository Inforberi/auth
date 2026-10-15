package postgres

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func (r *Repository) ChangeAdministrator(ctx context.Context, input service.AdministratorInput) (int64, error) {
	var version int64
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := requireActor(ctx, tx, input.Actor, string(input.UserID)); err != nil {
			return err
		}
		var roleID domain.RoleID
		err := tx.QueryRow(ctx, `SELECT r.id FROM auth.user_roles ur JOIN auth.roles r ON r.id=ur.role_id
			WHERE ur.user_id=$1 AND r.key='super_admin' AND r.system`, input.Actor.UserID).Scan(&roleID)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrForbidden
		}
		if err != nil {
			return err
		}
		role, err := readRole(ctx, tx, roleID)
		if err != nil {
			return err
		}
		if input.Grant && input.Actor.UserID == input.UserID {
			return domain.ErrForbidden
		}
		if err := requireDelegation(ctx, tx, input.Actor, settings.AssignmentsManage, role.Permissions); err != nil {
			return err
		}
		if role.Version != input.ExpectedRoleVersion || !slices.Contains(role.Permissions, settings.AssignmentsManage) {
			return domain.ErrConflict
		}
		var authVersion int64
		var ready bool
		err = tx.QueryRow(ctx, `SELECT u.access_version,u.auth_version,(`+usableAdministrator+`) FROM auth.users u WHERE u.id=$1 AND u.deleted_at IS NULL`, input.UserID).Scan(&version, &authVersion, &ready)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrTargetUnavailable
		}
		if err != nil {
			return err
		}
		if version != input.ExpectedAccessVersion || authVersion != int64(input.ExpectedAuthVersion) {
			return domain.ErrConflict
		}
		if input.Grant && !ready {
			return domain.ErrTargetUnavailable
		}
		if !input.Grant {
			if err := RequireAdministratorRemains(ctx, tx, input.UserID); err != nil {
				return err
			}
		}
		version, err = applyAssignment(ctx, tx, service.AssignmentInput{Actor: input.Actor, UserID: input.UserID, RoleID: role.ID, Grant: input.Grant}, role, version)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

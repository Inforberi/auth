package postgres

import (
	"context"
	"errors"

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
		version, err = CheckAdministratorTarget(ctx, tx, input, role)
		if err != nil {
			return err
		}
		version, err = applyAssignment(ctx, tx, service.AssignmentInput{Actor: input.Actor, UserID: input.UserID, RoleID: role.ID, Grant: input.Grant}, role, version)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

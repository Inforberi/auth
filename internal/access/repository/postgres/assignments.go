package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func (r *Repository) ChangeAssignment(ctx context.Context, input service.AssignmentInput) (int64, error) {
	var version int64
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		if err := requireActor(ctx, tx, input.Actor, string(input.UserID)); err != nil {
			return err
		}
		role, err := readRole(ctx, tx, input.RoleID)
		if err != nil {
			return err
		}
		// System assignments have their own authorization and last-administrator guards.
		if role.System || (input.Grant && input.UserID == input.Actor.UserID) {
			return domain.ErrForbidden
		}
		if role.Version != input.ExpectedRoleVersion {
			return domain.ErrConflict
		}
		if err := requireDelegation(ctx, tx, input.Actor, settings.AssignmentsManage, role.Permissions); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT access_version FROM auth.users WHERE id=$1 AND deleted_at IS NULL AND status IN ('active','pending')`, input.UserID).Scan(&version)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrTargetUnavailable
		}
		if err != nil {
			return err
		}
		if version != input.ExpectedAccessVersion {
			return domain.ErrConflict
		}
		version, err = applyAssignment(ctx, tx, input, role, version)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

func applyAssignment(ctx context.Context, tx pgx.Tx, input service.AssignmentInput, role domain.Role, version int64) (int64, error) {
	version, changed, err := ApplyAssignmentInTransaction(ctx, tx, input.UserID, role.ID, input.Grant, version)
	if err != nil {
		return 0, err
	}
	if !changed {
		return version, nil
	}
	event := "role_revoked"
	if input.Grant {
		event = "role_granted"
	}
	if err := recordAudit(ctx, tx, input.Actor, role, event, string(input.UserID), &version); err != nil {
		return 0, err
	}
	return version, nil
}

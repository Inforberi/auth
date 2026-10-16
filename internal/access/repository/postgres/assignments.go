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
	if input.Grant {
		var full bool
		if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.user_roles WHERE user_id=$1 AND role_id=$2)
				AND (SELECT count(*) FROM (SELECT 1 FROM auth.user_roles WHERE user_id=$1 LIMIT $3) bounded)>=$3`, input.UserID, role.ID, domain.MaxUserRoles).Scan(&full); err != nil {
			return 0, err
		}
		if full {
			return 0, domain.ErrConflict
		}
	}
	query, event := `DELETE FROM auth.user_roles WHERE user_id=$1 AND role_id=$2`, "role_revoked"
	if input.Grant {
		query, event = `INSERT INTO auth.user_roles(user_id,role_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, "role_granted"
	}
	result, err := tx.Exec(ctx, query, input.UserID, role.ID)
	if err != nil {
		return 0, err
	}
	if result.RowsAffected() == 0 {
		return version, nil
	}
	// A new assignment must not elevate a session issued before this grant.
	// Pending accounts have no live session; preserve their activation credentials.
	if err := tx.QueryRow(ctx, `UPDATE auth.users SET access_version=access_version+1,
		auth_version=auth_version+CASE WHEN $2 AND status='active' THEN 1 ELSE 0 END
		WHERE id=$1 RETURNING access_version`, input.UserID, input.Grant).Scan(&version); err != nil {
		return 0, err
	}
	if err := recordAudit(ctx, tx, input.Actor, role, event, string(input.UserID), &version); err != nil {
		return 0, err
	}
	return version, nil
}

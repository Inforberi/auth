package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

func CheckAdministratorTarget(ctx context.Context, tx pgx.Tx, input service.AdministratorInput, role domain.Role) (int64, error) {
	if !role.System || role.Key != "super_admin" || role.Version != input.ExpectedRoleVersion {
		return 0, domain.ErrConflict
	}
	var version, authVersion int64
	var ready, manageable bool
	err := tx.QueryRow(ctx, `SELECT u.access_version,u.auth_version,(`+usableAdministrator+`),
		EXISTS(SELECT 1 FROM auth.role_permissions WHERE role_id=$2 AND permission_key=$3)
		FROM auth.users u WHERE u.id=$1 AND u.deleted_at IS NULL FOR UPDATE OF u`,
		input.UserID, role.ID, settings.AssignmentsManage).Scan(&version, &authVersion, &ready, &manageable)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, domain.ErrTargetUnavailable
	}
	if err != nil {
		return 0, err
	}
	if version != input.ExpectedAccessVersion || authVersion != int64(input.ExpectedAuthVersion) || !manageable {
		return 0, domain.ErrConflict
	}
	if input.Grant && !ready {
		return 0, domain.ErrTargetUnavailable
	}
	if !input.Grant {
		if err := RequireAdministratorRemains(ctx, tx, input.UserID); err != nil {
			return 0, err
		}
	}
	return version, nil
}

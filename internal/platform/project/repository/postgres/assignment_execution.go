package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func changePlatformAssignment(ctx context.Context, tx pgx.Tx, actor domain.PlatformActor, binding credentials.Binding,
	command domain.RoleAssignment, permissions settings.Catalog, mfaReady bool,
) (domain.RoleAssignmentResult, error) {
	if tx == nil || !actor.Valid() || actor.RealmID != binding.RealmID || command.ProjectID != binding.ProjectID {
		return domain.RoleAssignmentResult{}, domain.ErrInvalidProject
	}
	command, err := command.Normalize()
	if err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	if err := checkProjectRuntime(ctx, tx, binding); err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return domain.RoleAssignmentResult{}, catalogError(ctx, err)
	}
	request, err := json.Marshal(command)
	if err != nil {
		return domain.RoleAssignmentResult{}, domain.ErrInvalidProject
	}
	target, err := json.Marshal(binding)
	if err != nil {
		return domain.RoleAssignmentResult{}, domain.ErrUnavailable
	}
	if result, _, found, err := readAssignmentReceipt(ctx, tx, actor.RealmID, actor.UserID, command, target, request); found || err != nil {
		return result, err
	}
	role, version, err := readAssignmentTarget(ctx, tx, command, permissions, mfaReady)
	if err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	version, changed, err := accesspostgres.ApplyAssignmentInTransaction(ctx, tx, command.UserID, role.ID, command.Action == domain.RoleGrant, version)
	if err != nil {
		if errors.Is(err, accessdomain.ErrConflict) {
			return domain.RoleAssignmentResult{}, err
		}
		return domain.RoleAssignmentResult{}, catalogError(ctx, err)
	}
	snapshot, err := json.Marshal(role)
	if err != nil {
		return domain.RoleAssignmentResult{}, domain.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.platform_role_assignments
		(operation_id,realm_id,actor_id,project_id,binding,request,user_id,role_id,role_snapshot,access_version,changed,admission_id)
		VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9::jsonb,$10,$11,$12)`,
		command.OperationID, actor.RealmID, actor.UserID, command.ProjectID, target, request, command.UserID, role.ID, snapshot, version, changed, actor.AdmissionID)
	if err != nil {
		return domain.RoleAssignmentResult{}, catalogError(ctx, err)
	}
	return domain.RoleAssignmentResult{ReceiptAdmissionID: actor.AdmissionID, RoleAssignmentSnapshot: domain.RoleAssignmentSnapshot{
		Action: command.Action, UserID: command.UserID, Role: role, AccessVersion: version, Changed: changed,
	}}, nil
}

func readAssignmentTarget(ctx context.Context, tx pgx.Tx, command domain.RoleAssignment, permissions settings.Catalog, mfaReady bool) (accessdomain.Role, int64, error) {
	role, err := accesspostgres.ReadRoleInTransaction(ctx, tx, command.RoleID)
	if err != nil {
		return accessdomain.Role{}, 0, err
	}
	// System assignments have a separate administrator flow. Neither action may
	// remove the last system administrator or impersonate a local project actor.
	if role.System {
		return accessdomain.Role{}, 0, accessdomain.ErrForbidden
	}
	if role.Version != command.ExpectedRoleVersion {
		return accessdomain.Role{}, 0, accessdomain.ErrConflict
	}
	grant := command.Action == domain.RoleGrant
	if grant {
		for _, key := range role.Permissions {
			if !permissions.Contains(key) {
				return accessdomain.Role{}, 0, accessdomain.ErrInvalidPermission
			}
		}
		if role.MFARequired && !mfaReady {
			return accessdomain.Role{}, 0, accessdomain.ErrMFANotReady
		}
	}
	var version int64
	err = tx.QueryRow(ctx, `SELECT access_version FROM auth.users WHERE id=$1 AND deleted_at IS NULL
		AND (status IN ('active','pending') OR (NOT $2 AND status='blocked')) FOR UPDATE`, command.UserID, grant).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return accessdomain.Role{}, 0, accessdomain.ErrTargetUnavailable
	}
	if err != nil {
		return accessdomain.Role{}, 0, catalogError(ctx, err)
	}
	if version != command.ExpectedAccessVersion {
		return accessdomain.Role{}, 0, accessdomain.ErrConflict
	}
	return role, version, nil
}

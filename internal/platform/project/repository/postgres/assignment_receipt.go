package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func readAssignmentReceipt(ctx context.Context, tx pgx.Tx, realm, actor domain.ID, command domain.RoleAssignment, target, request []byte) (domain.RoleAssignmentResult, domain.ID, bool, error) {
	var same bool
	var snapshot []byte
	var admission domain.ID
	result := domain.RoleAssignmentResult{Replayed: true}
	err := tx.QueryRow(ctx, `SELECT realm_id=$2 AND actor_id=$3 AND project_id=$4
		AND binding=$5::jsonb AND request=$6::jsonb,role_snapshot,admission_id::text,user_id::text,access_version,changed
		FROM auth.platform_role_assignments WHERE operation_id=$1`, command.OperationID, realm, actor, command.ProjectID, target, request).Scan(
		&same, &snapshot, &admission, &result.UserID, &result.AccessVersion, &result.Changed,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleAssignmentResult{}, "", false, nil
	}
	if err != nil {
		return domain.RoleAssignmentResult{}, "", false, catalogError(ctx, err)
	}
	if !same || result.UserID != command.UserID {
		return domain.RoleAssignmentResult{}, "", true, domain.ErrConflict
	}
	if json.Unmarshal(snapshot, &result.Role) != nil || result.Role.ID != command.RoleID {
		return domain.RoleAssignmentResult{}, "", true, domain.ErrConflict
	}
	result.Action = command.Action
	result.ReceiptAdmissionID = admission
	return result, admission, true, nil
}

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accesspostgres "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

// CreatePlatformRoleInTransaction is project-side persistence, not a bridge.
// The caller must own a committed current admission for this exact command.
// Later revoke cannot undo admitted work. No HTTP caller before MP2.7 gates.
func CreatePlatformRoleInTransaction(ctx context.Context, tx pgx.Tx, actor domain.PlatformActor, binding credentials.Binding,
	command domain.RoleCreation, catalog settings.Catalog, mfaReady bool,
) (domain.RoleCreationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if tx == nil || !actor.Valid() || actor.RealmID != binding.RealmID || command.ProjectID != binding.ProjectID {
		return domain.RoleCreationResult{}, domain.ErrInvalidProject
	}
	command, err := command.Normalize()
	if err != nil {
		return domain.RoleCreationResult{}, err
	}
	if err := schemapostgres.CheckRuntime(ctx, tx, binding); err != nil {
		return domain.RoleCreationResult{}, err
	}
	if err := accesspostgres.LockAccessChanges(ctx, tx); err != nil {
		return domain.RoleCreationResult{}, sqlerrors.Catalog(ctx, err)
	}
	request, err := json.Marshal(command)
	if err != nil {
		return domain.RoleCreationResult{}, domain.ErrInvalidProject
	}
	target, err := json.Marshal(binding)
	if err != nil {
		return domain.RoleCreationResult{}, domain.ErrInvalidProject
	}
	if replay, _, found, err := readRoleReceipt(ctx, tx, actor.RealmID, actor.UserID, command, target, request); found || err != nil {
		return replay, err
	}
	for _, permission := range command.Permissions {
		if !catalog.Contains(permission) {
			return domain.RoleCreationResult{}, accessdomain.ErrInvalidPermission
		}
	}
	if command.MFARequired && !mfaReady {
		return domain.RoleCreationResult{}, accessdomain.ErrMFANotReady
	}
	role, err := accesspostgres.InsertRoleInTransaction(ctx, tx, accessdomain.Role{
		Key: command.Key, Name: command.Name, Description: command.Description,
		Permissions: command.Permissions, MFARequired: command.MFARequired,
	})
	if err != nil {
		if errors.Is(err, accessdomain.ErrConflict) {
			return domain.RoleCreationResult{}, err
		}
		return domain.RoleCreationResult{}, sqlerrors.Catalog(ctx, err)
	}
	snapshot, err := json.Marshal(role)
	if err != nil {
		return domain.RoleCreationResult{}, domain.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.platform_role_creations
		(operation_id,realm_id,actor_id,project_id,binding,request,role_id,role_snapshot,admission_id)
		VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8::jsonb,$9)`, command.OperationID,
		actor.RealmID, actor.UserID, command.ProjectID, target, request, role.ID, snapshot, actor.AdmissionID)
	if err != nil {
		return domain.RoleCreationResult{}, sqlerrors.Catalog(ctx, err)
	}
	return domain.RoleCreationResult{Role: role, ReceiptAdmissionID: actor.AdmissionID}, nil
}

func readRoleReceipt(ctx context.Context, tx pgx.Tx, realm, actor domain.ID, command domain.RoleCreation, target, request []byte) (domain.RoleCreationResult, domain.ID, bool, error) {
	var same bool
	var snapshot []byte
	var admission domain.ID
	err := tx.QueryRow(ctx, `SELECT realm_id=$2 AND actor_id=$3 AND project_id=$4
		AND binding=$5::jsonb AND request=$6::jsonb,role_snapshot,admission_id::text
		FROM auth.platform_role_creations WHERE operation_id=$1`, command.OperationID,
		realm, actor, command.ProjectID, target, request).Scan(&same, &snapshot, &admission)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleCreationResult{}, "", false, nil
	}
	if err != nil {
		return domain.RoleCreationResult{}, "", false, sqlerrors.Catalog(ctx, err)
	}
	if !same {
		return domain.RoleCreationResult{}, "", true, domain.ErrConflict
	}
	var role accessdomain.Role
	if err := json.Unmarshal(snapshot, &role); err != nil {
		return domain.RoleCreationResult{}, "", true, domain.ErrUnavailable
	}
	return domain.RoleCreationResult{Role: role, Replayed: true, ReceiptAdmissionID: admission}, admission, true, nil
}

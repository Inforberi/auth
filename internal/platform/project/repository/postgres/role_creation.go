package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// PrepareRoleCreation writes only the catalog intent. Execution requires a new
// current-authority guard, project attestation, project audit and atomic receipt.
func (r *Repository) PrepareRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationIntent, error) {
	var result domain.RoleCreationIntent
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx) error {
		command, err := command.Normalize()
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		var binding []byte
		var realm string
		// Lifecycle writers lock the project first. Do not read ciphertext or grant
		// runtime UPDATE on provisioner-owned metadata just to lock it.
		err = tx.QueryRow(ctx, `SELECT realm.id::text,jsonb_build_object(
			'target',p.storage_target,'database',p.database_name,'reservation',s.reservation_id,
			'database_oid',s.database_oid,'owner_oid',s.owner_oid,'runtime_oid',s.runtime_oid,
			'schema',s.schema_version)
			FROM platform.projects p
			JOIN platform.project_preparations prep ON prep.project_id=p.id AND prep.secrets_created
			JOIN platform.project_secrets s ON s.project_id=p.id AND s.reservation_id=prep.reservation_id
				AND s.storage_target=prep.storage_target AND s.storage_target=p.storage_target
				AND s.schema_version=p.schema_version
			CROSS JOIN platform.operator_realm realm
			WHERE p.id=$1 AND p.version=$2 AND p.generation=$3
			AND p.desired_state='enabled' AND p.phase='ready' AND realm.initialized_at IS NOT NULL
			AND p.database_name='authp_'||replace(p.id::text,'-','')
			FOR SHARE OF p`, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration).Scan(&realm, &binding)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		if err != nil {
			return catalogError(ctx, err)
		}
		result.OperationID = command.OperationID
		err = tx.QueryRow(ctx, `INSERT INTO platform.project_role_intents
			(operation_id,project_id,realm_id,actor_id,version,generation,binding,request)
			VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
			ON CONFLICT(operation_id) DO NOTHING RETURNING created_at`, command.OperationID,
			command.ProjectID, realm, actor.UserID, command.ExpectedVersion, command.ExpectedGeneration,
			binding, request).Scan(&result.CreatedAt)
		if err == nil {
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return catalogError(ctx, err)
		}
		// A separate statement sees a concurrent INSERT winner, without a replay UPDATE.
		err = tx.QueryRow(ctx, `SELECT created_at FROM platform.project_role_intents
			WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
			AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
			command.OperationID, command.ProjectID, realm, actor.UserID,
			command.ExpectedVersion, command.ExpectedGeneration, binding, request).Scan(&result.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		result.Replayed = true
		return catalogError(ctx, err)
	})
	if err != nil {
		return domain.RoleCreationIntent{}, err
	}
	return result, nil
}

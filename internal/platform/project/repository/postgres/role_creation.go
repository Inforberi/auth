package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// PrepareRoleCreation writes only the catalog intent. A new committed admission
// and an attested project connection are required before execution.
func (r *Repository) PrepareRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationIntent, error) {
	var result domain.RoleCreationIntent
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		command, err := command.Normalize()
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		target, binding, err := lockRoleTarget(ctx, tx, command)
		if err != nil {
			return err
		}
		realm := target.RealmID
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

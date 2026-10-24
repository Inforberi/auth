package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// PrepareRoleCreation writes only the catalog intent. A new committed admission
// and an attested project connection are required before execution.
func (r *Repository) PrepareRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleIntent, error) {
	var result domain.RoleIntent
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		command, err := command.Normalize()
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		target, binding, err := lockRoleTarget(ctx, tx, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration)
		if err != nil {
			return err
		}
		result, err = insertRoleIntent(ctx, tx, roleIntentRecord{
			operation: command.OperationID, project: command.ProjectID, realm: target.RealmID, actor: domain.ID(actor.UserID),
			version: command.ExpectedVersion, generation: command.ExpectedGeneration, binding: binding, request: request,
		})
		return err
	})
	if err != nil {
		return domain.RoleIntent{}, err
	}
	return result, nil
}

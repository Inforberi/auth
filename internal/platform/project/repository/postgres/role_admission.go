package postgres

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// AdmittedRoleCreation is a process-local, one-use command, never a client token.
// Only a confirmed catalog commit produces a usable value.
type AdmittedRoleCreation struct {
	repository *Repository
	id         domain.ID
	actor      domain.PlatformActor
	binding    credentials.Binding
	command    domain.RoleCreation
	until      time.Time
	used       *atomic.Bool
}

func (a *AdmittedRoleCreation) ID() domain.ID {
	if a == nil {
		return ""
	}
	return a.id
}

func (r *Repository) AdmitRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (*AdmittedRoleCreation, error) {
	started := time.Now()
	a := &AdmittedRoleCreation{repository: r, used: new(atomic.Bool)}
	var remaining float64
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx, proofDeadline time.Time) error {
		var err error
		command, err = command.Normalize()
		if err != nil {
			return err
		}
		binding, snapshot, err := lockRoleTarget(ctx, tx, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration)
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		a.id, remaining, err = issueRoleAdmission(ctx, tx, roleIntentRecord{
			operation: command.OperationID, project: command.ProjectID, realm: binding.RealmID, actor: domain.ID(actor.UserID),
			version: command.ExpectedVersion, generation: command.ExpectedGeneration, binding: snapshot, request: request,
		}, proofDeadline)
		if err != nil {
			return err
		}
		a.actor = domain.PlatformActor{RealmID: binding.RealmID, UserID: domain.ID(actor.UserID), AdmissionID: a.id}
		a.binding, a.command = binding, command
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Anchor to the earlier local monotonic clock: SQL/commit/transport time can
	// only shorten the budget. Do not compare clocks of independent DB servers.
	a.until = started.Add(time.Duration(min(remaining, 3) * float64(time.Second)))
	if !time.Now().Before(a.until) {
		return nil, domain.ErrAdmissionExpired
	}
	return a, nil
}

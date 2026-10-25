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

type AdmittedRoleAssignment struct {
	repository *Repository
	id         domain.ID
	actor      domain.PlatformActor
	binding    credentials.Binding
	command    domain.RoleAssignment
	until      time.Time
	used       *atomic.Bool
}

func (r *Repository) PrepareRoleAssignment(ctx context.Context, actor operatordomain.Principal, command domain.RoleAssignment) (domain.RoleIntent, error) {
	var result domain.RoleIntent
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		_, record, _, err := assignmentIntent(ctx, tx, actor, command)
		if err != nil {
			return err
		}
		result, err = insertRoleIntent(ctx, tx, record)
		return err
	})
	if err != nil {
		return domain.RoleIntent{}, err
	}
	return result, nil
}

func (r *Repository) AdmitRoleAssignment(ctx context.Context, actor operatordomain.Principal, command domain.RoleAssignment) (*AdmittedRoleAssignment, error) {
	started := time.Now()
	a := &AdmittedRoleAssignment{repository: r, used: new(atomic.Bool)}
	var remaining float64
	err := r.mutate(ctx, actor, operatordomain.AccessManage, func(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
		command, record, binding, err := assignmentIntent(ctx, tx, actor, command)
		if err != nil {
			return err
		}
		a.id, remaining, err = issueRoleAdmission(ctx, tx, record, deadline)
		if err != nil {
			return err
		}
		a.command, a.binding = command, binding
		a.actor = domain.PlatformActor{RealmID: binding.RealmID, UserID: domain.ID(actor.UserID), AdmissionID: a.id}
		return nil
	})
	if err != nil {
		return nil, err
	}
	a.until = started.Add(time.Duration(min(remaining, 3) * float64(time.Second)))
	if !time.Now().Before(a.until) {
		return nil, domain.ErrAdmissionExpired
	}
	return a, nil
}

func assignmentIntent(ctx context.Context, tx pgx.Tx, actor operatordomain.Principal, command domain.RoleAssignment) (domain.RoleAssignment, operationIntentRecord, credentials.Binding, error) {
	command, err := command.Normalize()
	if err != nil {
		return command, operationIntentRecord{}, credentials.Binding{}, err
	}
	binding, snapshot, err := lockProjectTarget(ctx, tx, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration)
	if err != nil {
		return command, operationIntentRecord{}, binding, err
	}
	request, err := json.Marshal(command)
	if err != nil {
		return command, operationIntentRecord{}, binding, domain.ErrInvalidProject
	}
	return command, operationIntentRecord{
		operation: command.OperationID, project: command.ProjectID, realm: binding.RealmID, actor: domain.ID(actor.UserID),
		version: command.ExpectedVersion, generation: command.ExpectedGeneration, binding: snapshot, request: request,
	}, binding, nil
}

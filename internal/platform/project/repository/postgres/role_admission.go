package postgres

import (
	"context"
	"encoding/json"
	"errors"
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
		binding, snapshot, err := lockRoleTarget(ctx, tx, command)
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		var found int
		err = tx.QueryRow(ctx, `SELECT 1 FROM platform.project_role_intents
			WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
			AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
			command.OperationID, command.ProjectID, binding.RealmID, actor.UserID,
			command.ExpectedVersion, command.ExpectedGeneration, snapshot, request).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrConflict
		}
		if err != nil {
			return catalogError(ctx, err)
		}
		err = tx.QueryRow(ctx, `WITH issued AS (SELECT clock_timestamp() AS at)
			INSERT INTO platform.project_role_admissions(operation_id,created_at,expires_at)
			SELECT $1,at,LEAST($2::timestamptz,at+interval '3 seconds') FROM issued
			RETURNING admission_id::text,EXTRACT(EPOCH FROM expires_at-clock_timestamp())::double precision`,
			command.OperationID, proofDeadline).Scan(&a.id, &remaining)
		if err != nil {
			return catalogError(ctx, err)
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

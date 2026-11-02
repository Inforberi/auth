package postgres

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

var policyOperationQueries = operationQueries{
	insert: `INSERT INTO platform.project_auth_policy_intents
		(operation_id,project_id,realm_id,actor_id,version,generation,binding,request)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
		ON CONFLICT(operation_id) DO NOTHING RETURNING created_at`,
	match: `SELECT created_at FROM platform.project_auth_policy_intents
		WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
		AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
	admit: `WITH issued AS (SELECT clock_timestamp() AS at)
		INSERT INTO platform.project_auth_policy_admissions(operation_id,created_at,expires_at)
		SELECT $1,at,LEAST($2::timestamptz,at+interval '3 seconds') FROM issued
		RETURNING admission_id::text,EXTRACT(EPOCH FROM expires_at-clock_timestamp())::double precision`,
}

type AdmittedAuthPolicy struct {
	actor   domain.PlatformActor
	binding credentials.Binding
	command domain.AuthPolicyUpdate
	until   time.Time
	used    *atomic.Bool
}

func (r *Repository) AdmitAuthPolicy(ctx context.Context, actor operatordomain.Principal, command domain.AuthPolicyUpdate) (*AdmittedAuthPolicy, error) {
	started := time.Now()
	a := &AdmittedAuthPolicy{used: new(atomic.Bool)}
	var remaining float64
	err := r.mutate(ctx, actor, operatordomain.SettingsManage, func(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
		var err error
		command, err = command.Normalize()
		if err != nil {
			return err
		}
		binding, snapshot, err := lockProjectTarget(ctx, tx, command.ProjectID, command.ExpectedVersion, command.ExpectedGeneration)
		if err != nil {
			return err
		}
		request, err := json.Marshal(command)
		if err != nil {
			return domain.ErrInvalidProject
		}
		record := operationIntentRecord{
			operation: command.OperationID, project: command.ProjectID, realm: binding.RealmID, actor: domain.ID(actor.UserID),
			version: command.ExpectedVersion, generation: command.ExpectedGeneration, binding: snapshot, request: request,
		}
		if _, _, err := ensureOperationIntent(ctx, tx, policyOperationQueries, record); err != nil {
			return err
		}
		id, seconds, err := issueOperationAdmission(ctx, tx, policyOperationQueries, record, deadline)
		if err != nil {
			return err
		}
		a.actor = domain.PlatformActor{RealmID: binding.RealmID, UserID: domain.ID(actor.UserID), AdmissionID: id}
		a.binding, a.command, remaining = binding, command, seconds
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

package mutation

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func ReadReceipt(ctx context.Context, tx pgx.Tx, actor domain.PlatformActor, command domain.AuthPolicyUpdate, binding, request []byte) (domain.AuthPolicyResult, bool, error) {
	var same bool
	var snapshot []byte
	var result domain.AuthPolicyResult
	err := tx.QueryRow(ctx, `SELECT realm_id=$2 AND actor_id=$3 AND project_id=$4 AND binding=$5::jsonb AND request=$6::jsonb,
		next_policy,changed,admission_id::text FROM auth.platform_auth_policy_updates WHERE operation_id=$1`,
		command.OperationID, actor.RealmID, actor.UserID, command.ProjectID, binding, request).Scan(&same, &snapshot, &result.Changed, &result.ReceiptAdmissionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, sqlerrors.Catalog(ctx, err)
	}
	if !same {
		return domain.AuthPolicyResult{}, true, domain.ErrConflict
	}
	if json.Unmarshal(snapshot, &result.Snapshot) != nil || result.Snapshot.Version < 1 || result.Snapshot.Policy.Validate() != nil {
		return domain.AuthPolicyResult{}, true, domain.ErrUnavailable
	}
	result.Replayed = true
	return result, true, nil
}

func writeReceipt(ctx context.Context, tx pgx.Tx, actor domain.PlatformActor, command domain.AuthPolicyUpdate, binding, request []byte, before, after settingsdomain.Snapshot) error {
	previous, err := json.Marshal(before)
	if err != nil {
		return domain.ErrUnavailable
	}
	next, err := json.Marshal(after)
	if err != nil {
		return domain.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO auth.platform_auth_policy_updates
		(operation_id,realm_id,actor_id,admission_id,project_id,binding,request,previous_policy,next_policy,changed)
		VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10)`,
		command.OperationID, actor.RealmID, actor.UserID, actor.AdmissionID, command.ProjectID, binding, request, previous, next, before != after)
	return sqlerrors.Catalog(ctx, err)
}

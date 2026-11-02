package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

var roleOperationQueries = operationQueries{
	insert: `INSERT INTO platform.project_role_intents
        (operation_id,project_id,realm_id,actor_id,version,generation,binding,request)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
        ON CONFLICT(operation_id) DO NOTHING RETURNING created_at`,
	match: `SELECT created_at FROM platform.project_role_intents
        WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
        AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
	admit: `WITH issued AS (SELECT clock_timestamp() AS at)
        INSERT INTO platform.project_role_admissions(operation_id,created_at,expires_at)
        SELECT $1,at,LEAST($2::timestamptz,at+interval '3 seconds') FROM issued
        RETURNING admission_id::text,EXTRACT(EPOCH FROM expires_at-clock_timestamp())::double precision`,
}

func insertRoleIntent(ctx context.Context, tx pgx.Tx, command operationIntentRecord) (domain.RoleIntent, error) {
	created, replayed, err := ensureOperationIntent(ctx, tx, roleOperationQueries, command)
	return domain.RoleIntent{OperationID: command.operation, CreatedAt: created, Replayed: replayed}, err
}

func issueRoleAdmission(ctx context.Context, tx pgx.Tx, command operationIntentRecord, deadline time.Time) (domain.ID, float64, error) {
	return issueOperationAdmission(ctx, tx, roleOperationQueries, command, deadline)
}

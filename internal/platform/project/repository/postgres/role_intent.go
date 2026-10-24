package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type roleIntentRecord struct {
	operation, project, realm, actor domain.ID
	version, generation              int64
	binding, request                 []byte
}

func insertRoleIntent(ctx context.Context, tx pgx.Tx, c roleIntentRecord) (domain.RoleIntent, error) {
	result := domain.RoleIntent{OperationID: c.operation}
	err := tx.QueryRow(ctx, `INSERT INTO platform.project_role_intents
		(operation_id,project_id,realm_id,actor_id,version,generation,binding,request)
		VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
		ON CONFLICT(operation_id) DO NOTHING RETURNING created_at`,
		c.operation, c.project, c.realm, c.actor, c.version, c.generation, c.binding, c.request).Scan(&result.CreatedAt)
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleIntent{}, catalogError(ctx, err)
	}
	// A separate Read Committed statement sees an INSERT winner without replay UPDATE.
	err = tx.QueryRow(ctx, `SELECT created_at FROM platform.project_role_intents
		WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
		AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
		c.operation, c.project, c.realm, c.actor, c.version, c.generation, c.binding, c.request).Scan(&result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RoleIntent{}, domain.ErrConflict
	}
	result.Replayed = true
	return result, catalogError(ctx, err)
}

func issueRoleAdmission(ctx context.Context, tx pgx.Tx, c roleIntentRecord, deadline time.Time) (domain.ID, float64, error) {
	var found int
	err := tx.QueryRow(ctx, `SELECT 1 FROM platform.project_role_intents
		WHERE operation_id=$1 AND project_id=$2 AND realm_id=$3 AND actor_id=$4
		AND version=$5 AND generation=$6 AND binding=$7::jsonb AND request=$8::jsonb`,
		c.operation, c.project, c.realm, c.actor, c.version, c.generation, c.binding, c.request).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, domain.ErrConflict
	}
	if err != nil {
		return "", 0, catalogError(ctx, err)
	}
	var id domain.ID
	var remaining float64
	err = tx.QueryRow(ctx, `WITH issued AS (SELECT clock_timestamp() AS at)
		INSERT INTO platform.project_role_admissions(operation_id,created_at,expires_at)
		SELECT $1,at,LEAST($2::timestamptz,at+interval '3 seconds') FROM issued
		RETURNING admission_id::text,EXTRACT(EPOCH FROM expires_at-clock_timestamp())::double precision`, c.operation, deadline).Scan(&id, &remaining)
	return id, remaining, catalogError(ctx, err)
}

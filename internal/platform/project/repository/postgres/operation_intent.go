package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type operationIntentRecord struct {
	operation, project, realm, actor domain.ID
	version, generation              int64
	binding, request                 []byte
}

// Statements are fixed by the role/policy adapters; no request supplies SQL or a table name.
type operationQueries struct{ insert, match, admit string }

func (c operationIntentRecord) arguments() []any {
	return []any{c.operation, c.project, c.realm, c.actor, c.version, c.generation, c.binding, c.request}
}

func ensureOperationIntent(ctx context.Context, tx pgx.Tx, queries operationQueries, command operationIntentRecord) (time.Time, bool, error) {
	var created time.Time
	err := tx.QueryRow(ctx, queries.insert, command.arguments()...).Scan(&created)
	if err == nil {
		return created, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return created, false, catalogError(ctx, err)
	}
	// A separate Read Committed statement sees an INSERT winner without replay UPDATE.
	err = tx.QueryRow(ctx, queries.match, command.arguments()...).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return created, false, domain.ErrConflict
	}
	return created, true, catalogError(ctx, err)
}

func issueOperationAdmission(ctx context.Context, tx pgx.Tx, queries operationQueries, command operationIntentRecord, deadline time.Time) (domain.ID, float64, error) {
	var created time.Time
	err := tx.QueryRow(ctx, queries.match, command.arguments()...).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, domain.ErrConflict
	}
	if err != nil {
		return "", 0, catalogError(ctx, err)
	}
	var id domain.ID
	var remaining float64
	err = tx.QueryRow(ctx, queries.admit, command.operation, deadline).Scan(&id, &remaining)
	return id, remaining, catalogError(ctx, err)
}

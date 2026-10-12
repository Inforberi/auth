package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
)

func (r *Repository) CheckCatalog(ctx context.Context, known []string) error {
	var missing string
	err := r.db.QueryRow(ctx, `SELECT permission_key FROM auth.role_permissions
		WHERE NOT (permission_key=ANY($1::text[])) LIMIT 1`, known).Scan(&missing)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: stored role references undeclared permission %s", domain.ErrConflict, missing)
}

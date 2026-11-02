package sqlerrors

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

func Catalog(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	// Driver errors may include addresses or credentials; preserve only safe cancellation.
	return errors.Join(domain.ErrUnavailable, ctx.Err())
}

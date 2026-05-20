package register_postgres

import (
	"context"
	"fmt"
)

func (r *RegisterRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	sql := `
	SELECT EXISTS(
		SELECT 1
		FROM auth.password_credentials
		WHERE email = $1
	)
	`

	var exists bool
	err := r.db.QueryRow(ctx, sql, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query ExistByEmail: %w", err)
	}

	return exists, nil
}

package postgres

import (
	"context"
	"fmt"
)

func (r *PasswordRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	sql := `
	SELECT EXISTS(
		SELECT 1
		FROM auth.user_emails
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

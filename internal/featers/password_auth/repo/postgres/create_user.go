package postgres_password

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

func (r *PasswordRepo) CreateUser(ctx context.Context, email, passwordHash string) (domain.UserID, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("error to start transaction %w", err)
	}

	defer tx.Rollback(ctx)

	var userId domain.UserID

	sql := `
	INSERT INTO auth.users
	DEFAULT VALUES
	RETURNING id
	`
	err = tx.QueryRow(ctx, sql).Scan(&userId)
	if err != nil {
		return "", fmt.Errorf("insert users: %w", err)
	}

	sql = `
	INSERT INTO auth.password_credentials(
		user_id,
		email,
		password_hash
	)
	VALUES ($1, $2, $3)
	`
	_, err = tx.Exec(ctx, sql, userId, email, passwordHash)
	if err != nil {
		return "", fmt.Errorf("insert password_credentials: %w", err)
	}

	sql = `
	INSERT INTO auth.user_profile(
		user_id
	)
	VALUES ($1)
	`
	_, err = tx.Exec(ctx, sql, userId)
	if err != nil {
		return "", fmt.Errorf("insert user_profile: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("insert users: %w", err)
	}

	return userId, nil
}

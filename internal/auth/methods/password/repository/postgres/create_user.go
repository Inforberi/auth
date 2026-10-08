package postgres

import (
	"context"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func (r *PasswordRepo) CreateUser(ctx context.Context, email, passwordHash string) (accountdomain.UserID, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("error to start transaction %w", err)
	}

	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup) //nolint:gosec // Commit closes the transaction; keep the original error.
	}()

	var userId accountdomain.UserID

	sql := `
	INSERT INTO auth.users
	DEFAULT VALUES
	RETURNING id
	`
	err = tx.QueryRow(ctx, sql).Scan(&userId)
	if err != nil {
		return "", fmt.Errorf("insert users: %w", err)
	}

	var emailID accountdomain.AddressID
	err = tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id, email)
		VALUES ($1, $2) RETURNING id`, userId, email).Scan(&emailID)
	if err != nil {
		return "", registrationError(err)
	}

	sql = `
	INSERT INTO auth.password_credentials(
		user_id,
		email_id,
		password_hash
	)
	VALUES ($1, $2, $3)
	`
	_, err = tx.Exec(ctx, sql, userId, emailID, passwordHash)
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

package postgres_password

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"

	domain_password_auth "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"

	"github.com/jackc/pgx/v5"
)

func (l *PasswordRepo) FindByEmail(ctx context.Context, email string) (*domain_password_auth.FindByEmailResult, error) {
	sql := `
	SELECT user_id, password_hash
	FROM auth.password_credentials
	WHERE email = $1
	`
	var userID domain.UserID
	var passwordHash string

	err := l.db.QueryRow(ctx, sql, email).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("FindByEmail: %w", domain_password_auth.ErrNotFound)
		}
		return nil, fmt.Errorf("repo find by email %w", err)
	}

	return &domain_password_auth.FindByEmailResult{
		UserID:       userID,
		PasswordHash: passwordHash,
	}, nil
}

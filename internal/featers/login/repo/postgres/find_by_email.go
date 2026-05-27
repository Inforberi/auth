package login_postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	"github.com/jackc/pgx/v5"
)

func (l *LoginRepo) FindByEmail(ctx context.Context, email string) (*login_domain.FindByEmailResult, error) {
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
			return nil, fmt.Errorf("FindByEmail: %w", login_domain.ErrNotFound)
		}
		return nil, fmt.Errorf("repo find by email %w", err)
	}

	return &login_domain.FindByEmailResult{
		UserID:       userID,
		PasswordHash: passwordHash,
	}, nil
}

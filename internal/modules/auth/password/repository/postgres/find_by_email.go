package postgres

import (
	"context"
	"errors"
	"fmt"

	pgx "github.com/jackc/pgx/v5"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	domain_password_auth "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func (l *PasswordRepo) FindByEmail(ctx context.Context, email string) (*domain_password_auth.FindByEmailResult, error) {
	sql := `
	SELECT pc.user_id, pc.password_hash
	FROM auth.password_credentials pc
	JOIN auth.user_emails e ON e.id = pc.email_id AND e.user_id = pc.user_id
	WHERE e.email = $1
	`
	var userID accountmodel.UserID
	var passwordHash string

	err := l.db.QueryRow(ctx, sql, email).Scan(&userID, &passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("FindByEmail: %w", domain_password_auth.ErrUserNotFound)
		}
		return nil, fmt.Errorf("repo find by email %w", err)
	}

	return &domain_password_auth.FindByEmailResult{
		UserID:       userID,
		PasswordHash: passwordHash,
	}, nil
}

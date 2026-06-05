package postgres_password

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"github.com/jackc/pgx/v5"
)

func (p *PasswordRepo) FindUserByUserID(ctx context.Context, userID domain.UserID) (*password_domain.FindUserPassword, error) {
	sql := `
	SELECT password_hash
	FROM auth.password_credentials
	WHERE user_id = $1
	`
	var passwordHash string
	err := p.db.QueryRow(ctx, sql, userID).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, password_domain.ErrNotFound
		}
		return nil, fmt.Errorf("err find user %w", err)
	}

	return &password_domain.FindUserPassword{
		PasswordHash: passwordHash,
	}, nil
}

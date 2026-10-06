package postgres

import (
	"context"
	"errors"
	"fmt"

	pgx "github.com/jackc/pgx/v5"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func (p *PasswordRepo) FindUserByUserID(ctx context.Context, userID accountmodel.UserID) (*passwordmodel.FindUserPassword, error) {
	sql := `
	SELECT password_hash
	FROM auth.password_credentials
	WHERE user_id = $1
	`
	var passwordHash string
	err := p.db.QueryRow(ctx, sql, userID).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, passwordmodel.ErrNotFound
		}
		return nil, fmt.Errorf("err find user %w", err)
	}

	return &passwordmodel.FindUserPassword{
		PasswordHash: passwordHash,
	}, nil
}

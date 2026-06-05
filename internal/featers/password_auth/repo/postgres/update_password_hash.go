package postgres_password

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

func (p *PasswordRepo) UpdatePasswordHash(ctx context.Context, userID domain.UserID, passwordHash string) error {
	sql := `
	UPDATE auth.password_credentials
	SET password_hash = $2
	WHERE user_id = $1
	`
	result, err := p.db.Exec(ctx, sql, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	if result.RowsAffected() == 0 {
		return password_domain.ErrNotFound
	}

	return nil
}

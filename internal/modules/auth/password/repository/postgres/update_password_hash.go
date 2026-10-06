package postgres

import (
	"context"
	"fmt"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func (p *PasswordRepo) UpdatePasswordHash(ctx context.Context, userID accountmodel.UserID, passwordHash string) error {
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
		return passwordmodel.ErrNotFound
	}

	return nil
}

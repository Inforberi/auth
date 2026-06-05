package password_service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

func (p *PasswordService) ChangePassword(
	ctx context.Context,
	userID domain.UserID,
	currentTokenHash string,
	oldPassword string,
	newPassword string,
) error {
	// 1. get current password hash by userID
	result, err := p.repo.FindUserByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, password_domain.ErrNotFound) {
			return password_domain.ErrNotFound
		}
		return fmt.Errorf("change password find user %w", err)
	}

	// 2. compare oldPassword with current hash
	err = p.hash.Compare(oldPassword, result.PasswordHash)
	if err != nil {
		return password_domain.ErrInvalidEmailOrPassword
	}

	// 3. check oldPassword != newPassword
	if newPassword == oldPassword {
		return password_domain.ErrSamePassword
	}

	// 4. validate newPassword
	err = domain.ValidatePassword(newPassword)
	if err != nil {
		return fmt.Errorf("change password validate password %w", err)
	}

	// 5. generate new password hash
	passwordHash, err := p.hash.GenerateHash([]byte(newPassword))
	if err != nil {
		return fmt.Errorf("change password generateHash %w", err)
	}

	// 6. save new password hash
	if err := p.repo.UpdatePasswordHash(ctx, userID, passwordHash); err != nil {
		return fmt.Errorf("change password update password hash %w", err)
	}

	// 7. logout all sessions except currentTokenHash
	if err := p.session.LogoutAllExcept(ctx, currentTokenHash, userID); err != nil {
		return fmt.Errorf("change password session logout %w", err)
	}

	return nil
}

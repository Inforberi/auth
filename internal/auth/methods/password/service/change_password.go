package service

import (
	"context"
	"errors"
	"fmt"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func (p *PasswordService) ChangePassword(
	ctx context.Context,
	userID accountdomain.UserID,
	currentTokenHash string,
	oldPassword string,
	newPassword string,
) error {
	result, err := p.repo.FindUserByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, passworddomain.ErrNotFound) {
			return passworddomain.ErrNotFound
		}
		return fmt.Errorf("change password find user %w", err)
	}

	err = p.hash.Compare(oldPassword, result.PasswordHash)
	if err != nil {
		return passworddomain.ErrInvalidEmailOrPassword
	}

	if newPassword == oldPassword {
		return passworddomain.ErrSamePassword
	}

	err = passworddomain.ValidatePassword(newPassword)
	if err != nil {
		return fmt.Errorf("change password validate password %w", err)
	}

	passwordHash, err := p.hash.GenerateHash([]byte(newPassword))
	if err != nil {
		return fmt.Errorf("change password generateHash %w", err)
	}

	if err := p.repo.ChangePassword(ctx, userID, currentTokenHash, result.PasswordHash, passwordHash); err != nil {
		return fmt.Errorf("change password update password hash %w", err)
	}

	return nil
}

package password_service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

func (p *PasswordService) ChangePassword(
	ctx context.Context,
	userID domain.UserID,
	currentTokenHash string,
	oldPassword string,
	newPassword string,
) error {
	// 1. get current password hash by userID

	// 2. compare oldPassword with current hash

	// 3. validate newPassword

	// 4. check oldPassword != newPassword

	// 5. generate new password hash

	// 6. save new password hash

	// 7. logout all sessions except currentTokenHash

	return nil
}

package password_service

import (
	"context"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"github.com/stretchr/testify/assert"
)

func TestChangePassword_Success(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	userID := domain.UserID("user-1")
	oldPassword := "Qwertypay2"
	newPassword := "Qwertypay3"
	newPasswordHash := "123456"
	oldPasswordHash := "1234567"
	currentTokenHash := "token-hash"

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)
	repo.On("UpdatePasswordHash", context.Background(), userID, newPasswordHash).Return(nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)
	hasher.On("GenerateHash", []byte(newPassword)).Return(newPasswordHash, nil)

	session.On("LogoutAllExcept", context.Background(), currentTokenHash, userID).Return(nil)

	svc := New(repo, session, hasher, nil)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.NoError(t, err)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertExpectations(t)
}

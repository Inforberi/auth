package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestChangePassword_LogoutAllError(t *testing.T) {
	logoutAllErr := errors.New("change password session logout")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&passwordmodel.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)
	hasher.On("GenerateHash", []byte(newPassword)).Return(newPasswordHash, nil)

	repo.On("UpdatePasswordHash", context.Background(), userID, newPasswordHash).Return(nil)

	session.On("LogoutAllExcept", context.Background(), currentTokenHash, userID).Return(logoutAllErr)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.ErrorIs(t, err, logoutAllErr)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertExpectations(t)
}

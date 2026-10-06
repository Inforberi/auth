package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestChangePassword_ValidateError(t *testing.T) {
	newPassword := "12345"

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&passwordmodel.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.Error(t, err)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)
	repo.AssertNotCalled(t, "UpdatePasswordHash", mock.Anything, mock.Anything, mock.Anything)
	session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
}

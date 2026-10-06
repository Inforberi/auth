package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestChangePassword_UpdatePasswordError(t *testing.T) {
	updatePasswordErr := errors.New("Update password err")
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&passwordmodel.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)
	hasher.On("GenerateHash", []byte(newPassword)).Return(newPasswordHash, nil)

	repo.On("UpdatePasswordHash", context.Background(), userID, newPasswordHash).Return(updatePasswordErr)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.ErrorIs(t, err, updatePasswordErr)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
}

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestChangePassword_Success(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&passwordmodel.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)
	hasher.On("GenerateHash", []byte(newPassword)).Return(newPasswordHash, nil)

	repo.On("UpdatePasswordHash", context.Background(), userID, newPasswordHash).Return(nil)

	session.On("LogoutAllExcept", context.Background(), currentTokenHash, userID).Return(nil)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.NoError(t, err)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertExpectations(t)
}

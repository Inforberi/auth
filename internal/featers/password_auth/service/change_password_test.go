package password_service

import (
	"context"
	"errors"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	userID           = domain.UserID("user-1")
	oldPassword      = "Qwertypay2"
	newPassword      = "Qwertypay3"
	newPasswordHash  = "123456"
	oldPasswordHash  = "1234567"
	currentTokenHash = "token-hash"
)

func TestChangePassword_Success(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
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

func TestChangePassword_FindUserError(t *testing.T) {
	findUserErr := errors.New("change password find user")

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "no found",
			err:  password_domain.ErrNotFound,
		},
		{
			name: "change password find user",
			err:  findUserErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockPasswordRepo{}
			hasher := &mockHasher{}
			session := &mockSession{}

			repo.On("FindUserByUserID", mock.Anything, userID).Return(nil, tt.err)

			svc := newTestService(repo, session, hasher)

			err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

			assert.ErrorIs(t, err, tt.err)

			repo.AssertCalled(t, "FindUserByUserID", mock.Anything, mock.Anything)
			repo.AssertNotCalled(t, "UpdatePasswordHash", mock.Anything, mock.Anything, mock.Anything)

			hasher.AssertNotCalled(t, "Compare", mock.Anything, mock.Anything)
			hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)

			session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestChangePasswordCompareError(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(password_domain.ErrInvalidEmailOrPassword)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.ErrorIs(t, err, password_domain.ErrInvalidEmailOrPassword)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)

	repo.AssertNotCalled(t, "UpdatePasswordHash", mock.Anything, mock.Anything, mock.Anything)
	session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
}

func TestChangePassword_SamePasswordError(t *testing.T) {
	newPassword := oldPassword

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.ErrorIs(t, err, password_domain.ErrSamePassword)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)
	repo.AssertNotCalled(t, "UpdatePasswordHash", mock.Anything, mock.Anything, mock.Anything)
	session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
}

func TestChangePassword_ValidateError(t *testing.T) {
	newPassword := "12345"

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
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

func TestChangePassword_GenerateHashError(t *testing.T) {
	generateHashErr := errors.New("change password generateHash")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
		PasswordHash: oldPasswordHash,
	}, nil)

	hasher.On("Compare", oldPassword, oldPasswordHash).Return(nil)
	hasher.On("GenerateHash", []byte(newPassword)).Return("", generateHashErr)

	svc := newTestService(repo, session, hasher)

	err := svc.ChangePassword(context.Background(), userID, currentTokenHash, oldPassword, newPassword)

	assert.ErrorIs(t, err, generateHashErr)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	repo.AssertNotCalled(t, "UpdatePasswordHash", mock.Anything, mock.Anything, mock.Anything)
	session.AssertNotCalled(t, "LogoutAllExcept", mock.Anything, mock.Anything, mock.Anything)
}

func TestChangePassword_UpdatePasswordError(t *testing.T) {
	updatePasswordErr := errors.New("Update password err")
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
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

func TestChangePassword_LogoutAllError(t *testing.T) {
	logoutAllErr := errors.New("change password session logout")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("FindUserByUserID", context.Background(), userID).Return(&password_domain.FindUserPassword{
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

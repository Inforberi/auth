package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestChangePassword_FindUserError(t *testing.T) {
	findUserErr := errors.New("change password find user")

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "no found",
			err:  passwordmodel.ErrNotFound,
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

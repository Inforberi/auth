package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestRegister_ExistsByEmailError(t *testing.T) {
	email := "test@mail.ru"
	password := "Test12345"

	t.Run("found email", func(t *testing.T) {
		repo := &mockPasswordRepo{}
		session := &mockSession{}
		hasher := &mockHasher{}

		repo.On("ExistsByEmail", context.Background(), email).Return(true, nil)

		svc := newTestService(repo, session, hasher)

		registerResult, err := svc.Register(
			context.Background(),
			email,
			password,
			"mobile",
			"12345",
		)

		assert.Error(t, err)
		assert.ErrorIs(t, err, passwordmodel.ErrEmailAlreadyExists)
		assert.Nil(t, registerResult)

		repo.AssertCalled(t, "ExistsByEmail", context.Background(), email)
		repo.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
		hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)
		session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("repo error", func(t *testing.T) {
		repoErr := errors.New("db error")
		repo := &mockPasswordRepo{}
		session := &mockSession{}
		hasher := &mockHasher{}

		repo.On("ExistsByEmail", context.Background(), email).Return(false, repoErr)

		svc := newTestService(repo, session, hasher)

		registerResult, err := svc.Register(
			context.Background(),
			email,
			password,
			"mobile",
			"12345",
		)

		assert.Error(t, err)
		assert.ErrorIs(t, err, repoErr)
		assert.Nil(t, registerResult)
	})
}

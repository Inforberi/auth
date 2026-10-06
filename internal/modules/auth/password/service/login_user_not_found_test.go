package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestLogin_UserNotFound(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		nil,
		passwordmodel.ErrUserNotFound,
	)

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		passwordmodel.LoginInput{
			Email:     "test@mail.ru",
			Password:  "Password12345",
			UserAgent: "mobile",
			IP:        "127.0.0.1",
		},
	)

	assert.Error(t, err)
	assert.ErrorIs(
		t,
		err,
		passwordmodel.ErrInvalidEmailOrPassword,
	)
	assert.Nil(t, result)

	repo.AssertExpectations(t)

	hasher.AssertNotCalled(
		t,
		"Compare",
		mock.Anything,
		mock.Anything,
	)

	session.AssertNotCalled(
		t,
		"CreateSession",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

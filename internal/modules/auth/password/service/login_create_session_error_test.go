package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

func TestLogin_CreateSessionError(t *testing.T) {
	createErr := errors.New("create session error")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	user := accountmodel.UserID("user-1")

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		&passwordmodel.FindByEmailResult{
			UserID:       user,
			PasswordHash: "hashed",
		},
		nil,
	)

	hasher.On(
		"Compare",
		"Password12345",
		"hashed",
	).Return(nil)

	session.On(
		"CreateSession",
		context.Background(),
		user,
		"mobile",
		"127.0.0.1",
	).Return(nil, createErr)

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
	assert.ErrorIs(t, err, createErr)
	assert.Nil(t, result)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertExpectations(t)
}

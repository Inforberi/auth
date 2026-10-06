package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

func TestRegister_CreateUserError(t *testing.T) {
	createUserErr := errors.New("err create user")
	email := "test@mail.ru"
	password := "Test12345"
	hash := "Hashed"

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("ExistsByEmail", context.Background(), email).Return(false, nil)
	hasher.On("GenerateHash", []byte(password)).Return(hash, nil)
	repo.On("CreateUser", context.Background(), email, hash).Return(accountmodel.UserID(""), createUserErr)

	svc := newTestService(repo, session, hasher)

	registerResult, err := svc.Register(
		context.Background(),
		email,
		password,
		"mobile",
		"12345",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, createUserErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

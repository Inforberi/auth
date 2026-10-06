package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

func TestRegister_CreateSessionError(t *testing.T) {
	createSessionErr := errors.New("err create session")
	email := "test@mail.ru"
	password := "Test12345"
	hash := "Hashed"
	user := accountmodel.UserID("user-1")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("ExistsByEmail", context.Background(), email).Return(false, nil)
	hasher.On("GenerateHash", []byte(password)).Return(hash, nil)
	repo.On("CreateUser", context.Background(), email, hash).Return(user, nil)
	session.On("CreateSession", context.Background(), user, "mobile", "12345").Return(nil, createSessionErr)

	svc := newTestService(repo, session, hasher)

	registerResult, err := svc.Register(
		context.Background(),
		email,
		password,
		"mobile",
		"12345",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, createSessionErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)
	session.AssertExpectations(t)
	hasher.AssertExpectations(t)
}

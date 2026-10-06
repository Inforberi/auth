package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegister_GenerateHashError(t *testing.T) {
	hashErr := errors.New("Err generate Hash")
	email := "test@mail.ru"
	password := "Test12345"

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On("ExistsByEmail", context.Background(), email).Return(false, nil)
	hasher.On("GenerateHash", []byte(password)).Return("", hashErr)

	svc := newTestService(repo, session, hasher)

	registerResult, err := svc.Register(
		context.Background(),
		email,
		password,
		"mobile",
		"12345",
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, hashErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)
	session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	hasher.AssertExpectations(t)
}

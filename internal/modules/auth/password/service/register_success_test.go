package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func TestRegister_Success(t *testing.T) {
	hasher := &mockHasher{}
	repo := &mockPasswordRepo{}
	session := &mockSession{}

	hashPassword := "HashedPassword"
	email := "email@mail.ru"
	password := "Password1"
	user := accountmodel.UserID("user-1")
	rawToken := "RawToken"

	repo.On("ExistsByEmail", context.Background(), email).Return(false, nil)
	hasher.On("GenerateHash", []byte(password)).Return(hashPassword, nil)
	repo.On("CreateUser", context.Background(), email, hashPassword).Return(user, nil)
	session.On("CreateSession", context.Background(), user, "mobile", "12345").Return(&sessionmodel.CreatedSession{
		RawToken:  rawToken,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
	}, nil)

	svc := newTestService(repo, session, hasher)

	register, err := svc.Register(
		context.Background(),
		email,
		password,
		"mobile",
		"12345",
	)

	assert.NoError(t, err)
	assert.NotNil(t, register)
	assert.Equal(t, user, register.UserID)
	assert.Equal(t, rawToken, register.Token)
	assert.Equal(t, now.Add(7*24*time.Hour), register.ExpiresAt)

	hasher.AssertExpectations(t)
	repo.AssertExpectations(t)
	session.AssertExpectations(t)
}

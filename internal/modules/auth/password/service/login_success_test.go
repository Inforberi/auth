package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

func TestLogin_Success(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	user := accountmodel.UserID("user-1")

	input := passwordmodel.LoginInput{
		Email:     "test@mail.ru",
		Password:  "Password12345",
		UserAgent: "mobile",
		IP:        "127.0.0.1",
	}

	repo.On(
		"FindByEmail",
		context.Background(),
		input.Email,
	).Return(
		&passwordmodel.FindByEmailResult{
			UserID:       user,
			PasswordHash: "hashed-password",
		},
		nil,
	)

	hasher.On(
		"Compare",
		input.Password,
		"hashed-password",
	).Return(nil)

	session.On(
		"CreateSession",
		context.Background(),
		user,
		input.UserAgent,
		input.IP,
	).Return(
		&sessionmodel.CreatedSession{
			RawToken:  "raw-token",
			ExpiresAt: now.Add(7 * 24 * time.Hour),
		},
		nil,
	)

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		input,
	)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, user, result.UserID)
	assert.Equal(t, "raw-token", result.Token)
	assert.Equal(
		t,
		now.Add(7*24*time.Hour),
		result.ExpiresAt,
	)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)
	session.AssertExpectations(t)
}

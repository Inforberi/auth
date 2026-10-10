package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

func TestLogin_CreateSessionError(t *testing.T) {
	createErr := errors.New("create session error")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	user := accountdomain.UserID("user-1")

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		&passworddomain.Credential{
			AuthVersion:  7,
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
		"CreateSessionAtVersion",
		context.Background(),
		user,
		"mobile",
		"127.0.0.1",
		int64(7),
	).Return(nil, createErr)

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		LoginInput{
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

func TestLogin_FindByEmailError(t *testing.T) {
	findErr := errors.New("db error")

	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		nil,
		findErr,
	)

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		LoginInput{
			Email:     "test@mail.ru",
			Password:  "Password12345",
			UserAgent: "mobile",
			IP:        "127.0.0.1",
		},
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, findErr)
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
		"CreateSessionAtVersion",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestLogin_InvalidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
	}{
		{
			name:     "empty email",
			email:    "",
			password: "Password12345",
		},
		{
			name:     "invalid email",
			email:    "invalid",
			password: "Password12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockPasswordRepo{}
			hasher := &mockHasher{}
			session := &mockSession{}

			svc := newTestService(repo, session, hasher)

			result, err := svc.Login(
				context.Background(),
				LoginInput{
					Email:     tt.email,
					Password:  tt.password,
					UserAgent: "mobile",
					IP:        "127.0.0.1",
				},
			)

			assert.Error(t, err)
			assert.Nil(t, result)

			repo.AssertNotCalled(
				t,
				"FindByEmail",
				mock.Anything,
				mock.Anything,
			)

			hasher.AssertNotCalled(
				t,
				"Compare",
				mock.Anything,
				mock.Anything,
			)

			session.AssertNotCalled(
				t,
				"CreateSessionAtVersion",
				mock.Anything,
				mock.Anything,
				mock.Anything,
				mock.Anything,
				mock.Anything,
			)
		})
	}
}

func TestLogin_InvalidPassword(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	user := accountdomain.UserID("user-1")

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		&passworddomain.Credential{
			AuthVersion:  7,
			UserID:       user,
			PasswordHash: "hashed",
		},
		nil,
	)

	hasher.On(
		"Compare",
		"Password12345",
		"hashed",
	).Return(errors.New("invalid password"))

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		LoginInput{
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
		passworddomain.ErrInvalidEmailOrPassword,
	)
	assert.Nil(t, result)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)

	session.AssertNotCalled(
		t,
		"CreateSessionAtVersion",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestLogin_Success(t *testing.T) {
	repo := &mockPasswordRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	user := accountdomain.UserID("user-1")

	input := LoginInput{
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
		&passworddomain.Credential{
			AuthVersion:  7,
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
		"CreateSessionAtVersion",
		context.Background(),
		user,
		input.UserAgent,
		input.IP,
		int64(7),
	).Return(
		&sessionservice.CreatedSession{
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
		passworddomain.ErrUserNotFound,
	)

	svc := newTestService(repo, session, hasher)

	result, err := svc.Login(
		context.Background(),
		LoginInput{
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
		passworddomain.ErrInvalidEmailOrPassword,
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
		"CreateSessionAtVersion",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

package login_service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestLogin_Success(t *testing.T) {
	repo := &mockLoginRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	user := domain.UserID("user-1")

	input := login_domain.LoginInput{
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
		&login_domain.FindByEmailResult{
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
		&session_service.Session{
			RawToken:  "raw-token",
			ExpiresAt: now.Add(7 * 24 * time.Hour),
		},
		nil,
	)

	svc := New(
		repo,
		session,
		hasher,
		nil,
	)

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
			repo := &mockLoginRepo{}
			hasher := &mockHasher{}
			session := &mockSession{}

			svc := New(
				repo,
				session,
				hasher,
				nil,
			)

			result, err := svc.Login(
				context.Background(),
				login_domain.LoginInput{
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
				"CreateSession",
				mock.Anything,
				mock.Anything,
				mock.Anything,
				mock.Anything,
			)
		})
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	repo := &mockLoginRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		nil,
		login_domain.ErrNotFound,
	)

	svc := New(
		repo,
		session,
		hasher,
		nil,
	)

	result, err := svc.Login(
		context.Background(),
		login_domain.LoginInput{
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
		login_domain.ErrInvalidEmailOrPassword,
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

func TestLogin_FindByEmailError(t *testing.T) {
	findErr := errors.New("db error")

	repo := &mockLoginRepo{}
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

	svc := New(
		repo,
		session,
		hasher,
		nil,
	)

	result, err := svc.Login(
		context.Background(),
		login_domain.LoginInput{
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
		"CreateSession",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestLogin_InvalidPassword(t *testing.T) {
	repo := &mockLoginRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	user := domain.UserID("user-1")

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		&login_domain.FindByEmailResult{
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

	svc := New(
		repo,
		session,
		hasher,
		nil,
	)

	result, err := svc.Login(
		context.Background(),
		login_domain.LoginInput{
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
		login_domain.ErrInvalidEmailOrPassword,
	)
	assert.Nil(t, result)

	repo.AssertExpectations(t)
	hasher.AssertExpectations(t)

	session.AssertNotCalled(
		t,
		"CreateSession",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	)
}

func TestLogin_CreateSessionError(t *testing.T) {
	createErr := errors.New("create session error")

	repo := &mockLoginRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	user := domain.UserID("user-1")

	repo.On(
		"FindByEmail",
		context.Background(),
		"test@mail.ru",
	).Return(
		&login_domain.FindByEmailResult{
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

	svc := New(
		repo,
		session,
		hasher,
		nil,
	)

	result, err := svc.Login(
		context.Background(),
		login_domain.LoginInput{
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

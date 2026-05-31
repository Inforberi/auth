package register_service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegisterByEmail_Success(t *testing.T) {
	hasher := &mockHasher{}
	repo := &mockRegisterRepo{}
	session := &mockSession{}

	hashPassword := "HashedPassword"
	email := "email@mail.ru"
	password := "Password1"
	user := domain.UserID("user-1")
	rawToken := "RawToken"

	repo.On("ExistsByEmail", context.Background(), email).Return(false, nil)

	hasher.On("GenerateHash", []byte(password)).Return(hashPassword, nil)

	repo.On("CreateUser", context.Background(), email, hashPassword).Return(user, nil)

	session.On("CreateSession", context.Background(), user, "mobile", "12345").Return(&session_service.Session{
		RawToken:  rawToken,
		ExpiresAt: now.Add(7 * 24 * time.Hour),
	}, nil)

	svc := New(hasher, repo, session)
	register, err := svc.RegisterByEmail(
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
	assert.Equal(
		t,
		now.Add(7*24*time.Hour),
		register.ExpiresAt,
	)

	hasher.AssertExpectations(t)
	repo.AssertExpectations(t)
	session.AssertExpectations(t)

}

func TestRegisterByEmailEmailPasswordErrors(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
	}{
		{
			name:     "Invalid email",
			email:    "test",
			password: "Test12345",
		},
		{
			name:     "Invalid password",
			email:    "test@mail.ru",
			password: "Test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockRegisterRepo{}
			session := &mockSession{}
			hasher := &mockHasher{}

			repo.On("ExistsByEmail", context.Background(), tt.email).Return(true, nil)

			svc := New(hasher, repo, session)

			registerResult, err := svc.RegisterByEmail(context.Background(), tt.email, tt.password, "mobile", "12345")

			assert.Error(t, err)
			assert.Nil(t, registerResult)

			repo.AssertNotCalled(t, "ExistsByEmail", mock.Anything, mock.Anything)
			repo.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything, mock.Anything)

			hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)

			session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestRegisterByEmail_ExistsByEmailError(t *testing.T) {
	email := "test@mail.ru"
	password := "Test12345"

	tests := []struct {
		name  string
		found bool
		err   error
	}{
		{
			name:  "found email",
			found: true,
			err:   nil,
		},
		{
			name:  "returns err",
			found: false,
			err:   ErrEmailAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockRegisterRepo{}
			session := &mockSession{}
			hasher := &mockHasher{}

			repo.On("ExistsByEmail", context.Background(), email).Return(tt.found, tt.err)

			svc := New(hasher, repo, session)

			registerResult, err := svc.RegisterByEmail(
				context.Background(),
				email,
				password,
				"mobile",
				"12345",
			)

			assert.Error(t, err)
			assert.Nil(t, registerResult)
			if err != nil {
				assert.ErrorIs(t, err, ErrEmailAlreadyExists)
			}

			repo.AssertCalled(
				t,
				"ExistsByEmail",
				context.Background(),
				email,
			)

			repo.AssertNotCalled(
				t,
				"CreateUser",
				mock.Anything,
				mock.Anything,
			)

			hasher.AssertNotCalled(t, "GenerateHash", mock.Anything)
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

func TestRegisterByEmail_GenerateHashError(t *testing.T) {
	hashErr := errors.New("Err generate Hash")
	email := "test@mail.ru"
	password := "Test12345"
	userAgent := "mobile"
	ip := "12345"

	repo := &mockRegisterRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"ExistsByEmail",
		context.Background(),
		email,
	).Return(false, nil)

	hasher.On(
		"GenerateHash",
		[]byte(password),
	).Return("", hashErr)

	svc := New(hasher, repo, session)

	registerResult, err := svc.RegisterByEmail(
		context.Background(),
		email,
		password,
		userAgent,
		ip,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, hashErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)

	session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	hasher.AssertExpectations(t)
}

func TestRegisterByEmail_CreateUserError(t *testing.T) {
	createUserErr := errors.New("err create user")

	email := "test@mail.ru"
	password := "Test12345"
	userAgent := "mobile"
	ip := "12345"
	hash := "Hashed"

	repo := &mockRegisterRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"ExistsByEmail",
		context.Background(),
		email,
	).Return(false, nil)

	hasher.On(
		"GenerateHash",
		[]byte(password),
	).Return(hash, nil)

	repo.On(
		"CreateUser",
		context.Background(),
		email,
		hash,
	).Return(domain.UserID(""), createUserErr)

	svc := New(hasher, repo, session)

	registerResult, err := svc.RegisterByEmail(
		context.Background(),
		email,
		password,
		userAgent,
		ip,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, createUserErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)

	hasher.AssertExpectations(t)

	session.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRegisterByEmail_CreateSessionError(t *testing.T) {
	createSessionErr := errors.New("err create session")

	email := "test@mail.ru"
	password := "Test12345"
	userAgent := "mobile"
	ip := "12345"
	hash := "Hashed"
	user := domain.UserID("user-1")

	repo := &mockRegisterRepo{}
	hasher := &mockHasher{}
	session := &mockSession{}

	repo.On(
		"ExistsByEmail",
		context.Background(),
		email,
	).Return(false, nil)

	hasher.On(
		"GenerateHash",
		[]byte(password),
	).Return(hash, nil)

	repo.On(
		"CreateUser",
		context.Background(),
		email,
		hash,
	).Return(user, nil)

	session.On(
		"CreateSession",
		context.Background(),
		user,
		userAgent,
		ip,
	).Return(nil, createSessionErr)

	svc := New(hasher, repo, session)

	registerResult, err := svc.RegisterByEmail(
		context.Background(),
		email,
		password,
		userAgent,
		ip,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, createSessionErr)
	assert.Nil(t, registerResult)

	repo.AssertExpectations(t)

	session.AssertExpectations(t)

	hasher.AssertExpectations(t)

}

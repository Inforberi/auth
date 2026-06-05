package password_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/stretchr/testify/mock"
)

type mockPasswordRepo struct {
	mock.Mock
}

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func (m *mockPasswordRepo) FindByEmail(
	ctx context.Context,
	email string,
) (*password_domain.FindByEmailResult, error) {
	args := m.Called(ctx, email)

	result, _ := args.Get(0).(*password_domain.FindByEmailResult)

	return result, args.Error(1)
}

func (m *mockPasswordRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockPasswordRepo) CreateUser(ctx context.Context, email, passwordHash string) (domain.UserID, error) {
	args := m.Called(ctx, email, passwordHash)

	return args.Get(0).(domain.UserID), args.Error(1)
}

func (m *mockPasswordRepo) FindUserByUserID(ctx context.Context, userID domain.UserID) (*password_domain.FindUserPassword, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*password_domain.FindUserPassword), args.Error(1)
}

func (m *mockPasswordRepo) UpdatePasswordHash(ctx context.Context, userID domain.UserID, passwordHash string) error {
	args := m.Called(ctx, userID, passwordHash)
	return args.Error(0)
}

type mockHasher struct {
	mock.Mock
}

func (m *mockHasher) GenerateHash(password []byte) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *mockHasher) Compare(
	password string,
	encodedHash string,
) error {
	args := m.Called(password, encodedHash)
	return args.Error(0)
}

type mockSession struct {
	mock.Mock
}

func (m *mockSession) CreateSession(
	ctx context.Context,
	userID domain.UserID,
	userAgent string,
	ip string,
) (*session_service.Session, error) {
	args := m.Called(
		ctx,
		userID,
		userAgent,
		ip,
	)

	session, _ := args.Get(0).(*session_service.Session)

	return session, args.Error(1)
}

func (m *mockSession) LogoutAllExcept(ctx context.Context, tokenHash string, userID domain.UserID) error {
	args := m.Called(ctx, tokenHash, userID)
	return args.Error(0)
}

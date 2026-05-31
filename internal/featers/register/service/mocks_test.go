package register_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/stretchr/testify/mock"
)

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

type mockHasher struct{ mock.Mock }

func (m *mockHasher) GenerateHash(password []byte) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *mockHasher) Compare(password string, encodedHash string) error {
	args := m.Called(password, encodedHash)
	return args.Error(0)
}

type mockRegisterRepo struct{ mock.Mock }

func (m *mockRegisterRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *mockRegisterRepo) CreateUser(ctx context.Context, email, passwordHash string) (domain.UserID, error) {
	args := m.Called(ctx, email, passwordHash)

	return args.Get(0).(domain.UserID), args.Error(1)
}

type mockSession struct{ mock.Mock }

func (m *mockSession) CreateSession(ctx context.Context, userID domain.UserID, userAgent, IP string) (*session_service.Session, error) {
	args := m.Called(ctx, userID, userAgent, IP)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*session_service.Session), args.Error(1)
}

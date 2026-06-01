package login_service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	session_service "github.com/Inforberi/financial-intelligence/internal/featers/session/service"
	"github.com/stretchr/testify/mock"
)

type mockLoginRepo struct {
	mock.Mock
}

var now = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

func (m *mockLoginRepo) FindByEmail(
	ctx context.Context,
	email string,
) (*login_domain.FindByEmailResult, error) {
	args := m.Called(ctx, email)

	result, _ := args.Get(0).(*login_domain.FindByEmailResult)

	return result, args.Error(1)
}

type mockHasher struct {
	mock.Mock
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

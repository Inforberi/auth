package http

import (
	"context"

	"github.com/stretchr/testify/mock"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) LoginAdministrator(ctx context.Context, input passwordservice.LoginInput) (*passwordservice.LoginResult, error) {
	args := m.Called(ctx, input)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*passwordservice.LoginResult), args.Error(1)
}

func (m *mockPasswordService) Login(
	ctx context.Context,
	input passwordservice.LoginInput,
) (*passwordservice.LoginResult, error) {
	args := m.Called(ctx, input)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*passwordservice.LoginResult), args.Error(1)
}

func (m *mockPasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	ip string,
) (*passwordservice.RegisterResult, error) {
	args := m.Called(ctx, email, password, userAgent, ip)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*passwordservice.RegisterResult), args.Error(1)
}

func (m *mockPasswordService) ChangePassword(
	ctx context.Context,
	userID accountdomain.UserID,
	currentTokenHash string,
	oldPassword string,
	newPassword string,
) error {
	args := m.Called(ctx, userID, currentTokenHash, oldPassword, newPassword)

	return args.Error(0)
}

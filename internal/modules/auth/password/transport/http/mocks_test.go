package http

import (
	"context"

	"github.com/stretchr/testify/mock"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) Login(
	ctx context.Context,
	input passwordmodel.LoginInput,
) (*passwordmodel.LoginResult, error) {
	args := m.Called(ctx, input)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*passwordmodel.LoginResult), args.Error(1)
}

func (m *mockPasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	ip string,
) (*passwordmodel.RegisterResult, error) {
	args := m.Called(ctx, email, password, userAgent, ip)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*passwordmodel.RegisterResult), args.Error(1)
}

func (m *mockPasswordService) ChangePassword(
	ctx context.Context,
	userID accountmodel.UserID,
	currentTokenHash string,
	oldPassword string,
	newPassword string,
) error {
	args := m.Called(ctx, userID, currentTokenHash, oldPassword, newPassword)

	return args.Error(0)
}

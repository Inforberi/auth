package password_http

import (
	"context"

	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"github.com/stretchr/testify/mock"
)

type mockPasswordService struct {
	mock.Mock
}

func (m *mockPasswordService) Login(
	ctx context.Context,
	input password_domain.LoginInput,
) (*password_domain.LoginResult, error) {
	args := m.Called(ctx, input)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*password_domain.LoginResult), args.Error(1)
}

func (m *mockPasswordService) Register(
	ctx context.Context,
	email,
	password,
	userAgent,
	IP string,
) (*password_domain.RegisterResult, error) {
	args := m.Called(ctx, email, password, userAgent, IP)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*password_domain.RegisterResult), args.Error(1)
}

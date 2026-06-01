package login_http

import (
	"context"

	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	"github.com/stretchr/testify/mock"
)

type mockLoginService struct{ mock.Mock }

func (m *mockLoginService) Login(ctx context.Context, input login_domain.LoginInput) (*login_domain.LoginResult, error) {

	args := m.Called(ctx, input)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*login_domain.LoginResult), args.Error(1)

}

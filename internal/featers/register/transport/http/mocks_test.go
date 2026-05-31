package register_http

import (
	"context"

	register_domain "github.com/Inforberi/financial-intelligence/internal/featers/register/domain"
	"github.com/stretchr/testify/mock"
)

type mockRegisterService struct {
	mock.Mock
}

func (m *mockRegisterService) RegisterByEmail(
	ctx context.Context,
	email,
	password,
	userAgent,
	IP string,
) (*register_domain.RegisterResult, error) {
	args := m.Called(ctx, email, password, userAgent, IP)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*register_domain.RegisterResult), args.Error(1)
}

package register_http

import (
	"context"

	register_domain "github.com/Inforberi/financial-intelligence/internal/featers/register/domain"
	"go.uber.org/zap"
)

type registerService interface {
	RegisterByEmail(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*register_domain.RegisterResult, error)
}

type RegisterHandler struct {
	service registerService
	log     *zap.Logger
}

func New(service registerService, log *zap.Logger) *RegisterHandler {
	return &RegisterHandler{service: service, log: log}
}

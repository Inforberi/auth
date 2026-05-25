package register_http

import (
	"context"

	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
	"go.uber.org/zap"
)

type registerService interface {
	RegisterByEmail(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*register_service.RegisterResult, error)
}

type registerHandler struct {
	service registerService
	log     *zap.Logger
}

func New(service registerService, log *zap.Logger) *registerHandler {
	return &registerHandler{service: service, log: log}
}

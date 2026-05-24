package register_http

import (
	"context"

	register_service "github.com/Inforberi/financial-intelligence/internal/featers/register/service"
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
}

func New(service registerService) *registerHandler {
	return &registerHandler{service: service}
}

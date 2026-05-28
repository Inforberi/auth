package login_http

import (
	"context"

	login_domain "github.com/Inforberi/financial-intelligence/internal/featers/login/domain"
	"go.uber.org/zap"
)

type LoginService interface {
	Login(ctx context.Context, input login_domain.LoginInput) (*login_domain.LoginResult, error)
}

type LoginHandler struct {
	service LoginService
	log     *zap.Logger
}

func New(service LoginService, log *zap.Logger) *LoginHandler {
	return &LoginHandler{service: service, log: log}
}

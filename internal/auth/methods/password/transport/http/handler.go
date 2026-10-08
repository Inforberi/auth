package http

import (
	"context"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type PasswordService interface {
	Login(ctx context.Context, input passwordservice.LoginInput) (*passwordservice.LoginResult, error)
	Register(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*passwordservice.RegisterResult, error)
	ChangePassword(
		ctx context.Context,
		userID accountdomain.UserID,
		currentTokenHash string,
		oldPassword string,
		newPassword string,
	) error
}

type PasswordHandler struct {
	service PasswordService
	log     *zap.Logger
}

func New(service PasswordService, log *zap.Logger) *PasswordHandler {
	return &PasswordHandler{service: service, log: log}
}

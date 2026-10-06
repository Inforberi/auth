package http

import (
	"context"

	"go.uber.org/zap"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
)

type PasswordService interface {
	Login(ctx context.Context, input passwordmodel.LoginInput) (*passwordmodel.LoginResult, error)
	Register(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*passwordmodel.RegisterResult, error)
	ChangePassword(
		ctx context.Context,
		userID accountmodel.UserID,
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

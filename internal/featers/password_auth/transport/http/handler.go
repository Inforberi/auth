package password_http

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
	"go.uber.org/zap"
)

type PasswordService interface {
	Login(ctx context.Context, input password_domain.LoginInput) (*password_domain.LoginResult, error)
	Register(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*password_domain.RegisterResult, error)
	ChangePassword(
		ctx context.Context,
		userID domain.UserID,
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

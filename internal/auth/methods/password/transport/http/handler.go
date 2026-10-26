package http

import (
	"context"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
)

type PublicPasswordService interface {
	Login(ctx context.Context, input passwordservice.LoginInput) (*passwordservice.LoginResult, error)
	Register(
		ctx context.Context,
		email,
		password,
		userAgent,
		IP string,
	) (*passwordservice.RegisterResult, error)
}

type PasswordService interface {
	PublicPasswordService
	LoginAdministrator(ctx context.Context, input passwordservice.LoginInput) (*passwordservice.LoginResult, error)
	ChangePassword(
		ctx context.Context,
		userID accountdomain.UserID,
		currentTokenHash string,
		oldPassword string,
		newPassword string,
	) error
}

type PublicPasswordHandler struct {
	service PublicPasswordService
	log     *zap.Logger
}

type PasswordHandler struct {
	*PublicPasswordHandler
	*ChangePasswordHandler
	service PasswordService
}

func New(service PasswordService, log *zap.Logger) *PasswordHandler {
	return &PasswordHandler{PublicPasswordHandler: NewPublic(service, log), ChangePasswordHandler: NewChangePassword(service, nil, log), service: service}
}

func NewPublic(service PublicPasswordService, log *zap.Logger) *PublicPasswordHandler {
	return &PublicPasswordHandler{service: service, log: log}
}

type RecoveryService interface {
	Forgot(context.Context, string, string) error
	Reset(context.Context, string, string, string, string) error
}
type RecoveryHandler struct {
	service RecoveryService
	log     *zap.Logger
}

func NewRecovery(service RecoveryService, log *zap.Logger) *RecoveryHandler {
	return &RecoveryHandler{service: service, log: log}
}

type RecoveryResponse struct {
	Status string `json:"status" example:"ok"`
} // @name password_http.RecoveryResponse

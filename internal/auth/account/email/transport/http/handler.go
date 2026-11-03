package accountemailhttp

import (
	"context"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type EmailVerificationService interface {
	Resend(context.Context, string, string) error
	Confirm(context.Context, string, string) error
}

type VerificationService interface {
	EmailVerificationService
	AllowRegistration(context.Context, string) error
	RequireVerified(context.Context, domain.UserID) error
}

type VerificationHandler struct {
	service EmailVerificationService
	log     *zap.Logger
}

type Handler struct {
	*VerificationHandler
	service VerificationService
}

func New(service VerificationService, log *zap.Logger) *Handler {
	return &Handler{VerificationHandler: NewVerification(service, log), service: service}
}

func NewVerification(service EmailVerificationService, log *zap.Logger) *VerificationHandler {
	return &VerificationHandler{service: service, log: log}
}

type VerificationResponse struct {
	Status string `json:"status" example:"ok"`
} // @name account_http.VerificationResponse

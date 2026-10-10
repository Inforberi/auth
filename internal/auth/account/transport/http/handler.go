package http

import (
	"context"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type VerificationService interface {
	AllowRegistration(context.Context, string) error
	Resend(context.Context, string, string) error
	Confirm(context.Context, string, string) error
	RequireVerified(context.Context, domain.UserID) error
}

type Handler struct {
	service VerificationService
	log     *zap.Logger
}

func New(service VerificationService, log *zap.Logger) *Handler {
	return &Handler{service: service, log: log}
}

type VerificationResponse struct {
	Status string `json:"status" example:"ok"`
} // @name account_http.VerificationResponse

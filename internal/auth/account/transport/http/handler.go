package http

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
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

func accountActor(w http.ResponseWriter, r *http.Request) (accessservice.Principal, bool) {
	auth, ok := sessionhttp.GetAuthContext(r.Context())
	if !ok {
		httpx.Error(w, 401, "unauthorized", "unauthorized")
		return accessservice.Principal{}, false
	}
	return accessservice.Principal{UserID: auth.UserID, TokenHash: auth.TokenHash}, true
}

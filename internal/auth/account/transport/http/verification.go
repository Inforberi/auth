package http

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
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

type ResendRequest struct {
	Email string `json:"email" binding:"required" example:"user@example.com"`
} // @name account_http.ResendRequest

type ConfirmRequest struct {
	Token string `json:"token" binding:"required"`
} // @name account_http.ConfirmRequest

type VerificationResponse struct {
	Status string `json:"status" example:"ok"`
} // @name account_http.VerificationResponse

// @Summary Request email verification
// @Description Always returns accepted for unknown, verified, blocked and cooldown addresses. Enqueues encrypted delivery for eligible addresses. Limits use socket peer IP; forwarded headers are not trusted.
// @Tags Account
// @Accept json
// @Produce json
// @Param body body ResendRequest true "email"
// @Success 202 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/resend [post]
func (h *Handler) Resend(w http.ResponseWriter, r *http.Request) {
	var input ResendRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if _, err := domain.NewEmail(input.Email); err != nil {
		httpx.Error(w, 400, "invalid_email", "invalid email")
		return
	}
	if err := h.service.Resend(r.Context(), input.Email, httpx.IP(r)); err != nil {
		h.respondError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 202, VerificationResponse{Status: "accepted"})
}

// @Summary Confirm email ownership
// @Description Consumes a 256-bit token once. Expired, replaced, replayed, blocked or unknown tokens share one error. Does not create a session. POST only; opening an email link must not confirm automatically.
// @Tags Account
// @Accept json
// @Produce json
// @Param body body ConfirmRequest true "token"
// @Success 200 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_verification"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/verify [post]
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	var input ConfirmRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if len(input.Token) > 128 {
		httpx.Error(w, 400, "invalid_verification", "invalid verification")
		return
	}
	if err := h.service.Confirm(r.Context(), input.Token, httpx.IP(r)); err != nil {
		h.respondError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, VerificationResponse{Status: "ok"})
}

func (h *Handler) respondError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrVerificationLimited):
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, 429, "rate_limited", "rate limited")
	case errors.Is(err, domain.ErrInvalidVerification):
		httpx.Error(w, 400, "invalid_verification", "invalid verification")
	default:
		h.log.Warn("email verification dependency failed")
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
	}
}

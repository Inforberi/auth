package http

import (
	"context"
	"errors"
	"net/http"

	"go.uber.org/zap"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

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

type (
	ForgotRequest struct {
		Email string `json:"email" binding:"required" example:"user@example.com"`
	} // @name password_http.ForgotRequest
	ResetRequest struct {
		Token           string `json:"token" binding:"required"`
		NewPassword     string `json:"newPassword" binding:"required" example:"ExamplePass2"`
		ConfirmPassword string `json:"confirmPassword" binding:"required" example:"ExamplePass2"`
	} // @name password_http.ResetRequest
)

type RecoveryResponse struct {
	Status string `json:"status" example:"ok"`
} // @name password_http.RecoveryResponse

// @Summary Request password recovery
// @Description Generic accepted response for unknown, blocked and cooldown addresses. Enqueues an encrypted email after SQL commit; does not guarantee delivery. Socket IP limits; forwarded headers are not trusted.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body ForgotRequest true "email"
// @Success 202 {object} RecoveryResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/forgot-password [post]
func (h *RecoveryHandler) Forgot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input ForgotRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Forgot(r.Context(), input.Email, httpx.IP(r)); err != nil {
		h.respondError(w, err)
		return
	}
	httpx.JSON(w, 202, RecoveryResponse{Status: "accepted"})
}

// @Summary Reset password
// @Description Single-use 256-bit token. SQL commit atomically updates the password, consumes the token, revokes all sessions and records audit. Does not verify email or create a session; sign in again. New password: 8-128 bytes, letter, digit and uppercase. POST only, never automatic GET confirmation.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body ResetRequest true "token and new password"
// @Success 200 {object} RecoveryResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_reset, password_mismatch, password_policy"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/reset-password [post]
func (h *RecoveryHandler) Reset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input ResetRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if len(input.Token) > 128 {
		httpx.Error(w, 400, "invalid_reset", "invalid reset")
		return
	}
	if err := h.service.Reset(r.Context(), input.Token, input.NewPassword, input.ConfirmPassword, httpx.IP(r)); err != nil {
		h.respondError(w, err)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryResponse{Status: "ok"})
}

func (h *RecoveryHandler) respondError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, accountdomain.ErrEmailInvalid):
		httpx.Error(w, 400, "invalid_email", "invalid email")
	case errors.Is(err, domain.ErrRecoveryLimited):
		w.Header().Set("Retry-After", "900")
		httpx.Error(w, 429, "rate_limited", "rate limited")
	case errors.Is(err, domain.ErrInvalidReset):
		httpx.Error(w, 400, "invalid_reset", "invalid reset")
	case errors.Is(err, domain.ErrPasswordConfirmation):
		httpx.Error(w, 400, "password_mismatch", "passwords do not match")
	case passwordPolicyError(err):
		httpx.Error(w, 400, "password_policy", "invalid password")
	default:
		h.log.Warn("password recovery dependency failed")
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
	}
}

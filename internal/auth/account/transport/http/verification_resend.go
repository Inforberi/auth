package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ResendRequest struct {
	Email string `json:"email" binding:"required" example:"user@example.com"`
} // @name account_http.ResendRequest

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
	if err := h.service.Resend(r.Context(), input.Email, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "resend", resendErrors)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 202, VerificationResponse{Status: "accepted"})
}

package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ForgotRequest struct {
	Email string `json:"email" binding:"required" example:"user@example.com"`
} // @name password_http.ForgotRequest
// @Summary Request password recovery
// @Description Generic accepted response for unknown, blocked and cooldown addresses. Enqueues an encrypted email after SQL commit; does not guarantee delivery. Socket IP limits; forwarded headers are not trusted.
// @Tags Auth
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
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
		h.respondError(w, r, err, "forgot password", forgotErrors)
		return
	}
	httpx.JSON(w, 202, RecoveryResponse{Status: "accepted"})
}

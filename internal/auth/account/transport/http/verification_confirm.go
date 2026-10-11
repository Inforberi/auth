package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ConfirmRequest struct {
	Token string `json:"token" binding:"required"`
} // @name account_http.ConfirmRequest

// @Summary Confirm email ownership
// @Description Consumes a 256-bit token once. Expired, replaced, replayed, blocked or unknown tokens share one error. Does not create a session. POST only; opening an email link must not confirm automatically.
// @Tags Account
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Accept json
// @Produce json
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
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
	if err := h.service.Confirm(r.Context(), input.Token, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "confirm", verificationErrors)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, 200, VerificationResponse{Status: "ok"})
}

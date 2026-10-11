package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type RequestCodeRequest struct {
	Email string `json:"email"`
} // @name emailotp_http.RequestCodeRequest

// @Summary Request a passwordless email login code
// @Description Optional profile, existing active account with verified current password email only. Generic accepted response; sets a browser-bound HttpOnly flow cookie. Does not register, verify email or create a session.
// @Tags Email OTP
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body RequestCodeRequest true "email"
// @Success 202 {object} StatusResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email-otp/request [post]
func (h *Handler) Request(w http.ResponseWriter, r *http.Request) {
	var input RequestCodeRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Request(r.Context(), input.Email, httpx.IP(r))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	setFlowCookie(w, result.Binding, result.ExpiresAt)
	httpx.JSON(w, 202, StatusResponse{Status: "accepted"})
}

package http

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type EmailChangeConfirmRequest struct {
	Token string `json:"token"`
} // @name account_http.EmailChangeConfirmRequest

// @Summary Confirm a login email change
// @Description Optional profile. Explicit POST with a purpose-bound one-time token. Original session must still be valid. Claims new email, revokes all sessions and sends old-address notice atomically. No session created; GET links never mutate state.
// @Tags Account
// @Accept json
// @Produce json
// @Param body body EmailChangeConfirmRequest true "confirmation token"
// @Success 200 {object} VerificationResponse
// @Failure 400 {object} httpx.ErrorResponse "codes: invalid_json, invalid_email_change"
// @Failure 401 {object} httpx.ErrorResponse "code: fresh_auth_required"
// @Failure 403 {object} httpx.ErrorResponse "code: invalid_origin"
// @Failure 429 {object} httpx.ErrorResponse "code: rate_limited"
// @Failure 503 {object} httpx.ErrorResponse "code: temporarily_unavailable"
// @Router /api/v1/auth/email/change/confirm [post]
func (h *EmailChangeHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	var input EmailChangeConfirmRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if err := h.service.Confirm(r.Context(), input.Token, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "confirm email change")
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, VerificationResponse{Status: "ok"})
}

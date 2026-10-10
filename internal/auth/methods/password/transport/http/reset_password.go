package http

import (
	"net/http"

	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ResetRequest struct {
	Token           string `json:"token" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required" example:"ExamplePass2"`
	ConfirmPassword string `json:"confirmPassword" binding:"required" example:"ExamplePass2"`
} // @name password_http.ResetRequest

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
	if err := h.service.Reset(r.Context(), input.Token, input.NewPassword, input.ConfirmPassword, httpx.IP(r)); err != nil {
		h.respondError(w, r, err, "reset password", resetErrors)
		return
	}
	sessionhttp.ClearSessionCookie(w)
	httpx.JSON(w, 200, RecoveryResponse{Status: "ok"})
}

package mfatelegramhttp

import (
	"net/http"
)

// @Summary Disable the Telegram factor
// @Description Requires fresh current proofs; cannot remove the final policy-required factor.
// @Tags MFA
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @ID deleteAuthMfaTelegram
// @Router /api/v1/auth/mfa/telegram [delete]
func (h *TelegramHandler) Disable(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.service.Disable)
}

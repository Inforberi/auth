package mfatelegramhttp

import (
	"net/http"
)

// @Summary Enable or replace the confirmed Telegram factor
// @Description Requires the same fresh source proofs and confirmed channel. Revokes existing credentials; no session issued.
// @Tags MFA
// @Success 200 {object} mfahttp.StatusResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Router /api/v1/auth/mfa/telegram [post]
func (h *TelegramHandler) Enable(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.service.Enable)
}

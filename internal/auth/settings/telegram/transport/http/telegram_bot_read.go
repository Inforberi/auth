package settingstelegramhttp

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read masked Telegram bot settings
// @Description Requires current auth.settings.manage. Mutations require fresh password/strong MFA and expectedVersion. Secrets are never returned.
// @Tags Auth settings
// @Produce json
// @Success 200 {object} TelegramBotResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID getAdminAuthSettingsMfaTelegramBot
// @Router /api/v1/admin/auth/settings/mfa/telegram/bot [get]
func (h *TelegramHandler) ReadBot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := settingshttp.Principal(w, r)
	if !ok {
		return
	}
	result, err := h.service.ReadBot(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

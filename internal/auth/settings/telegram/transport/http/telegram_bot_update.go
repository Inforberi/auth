package settingstelegramhttp

import (
	"net/http"

	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Verify and update Telegram bot secrets
// @Description Requires current auth.settings.manage. Mutations require fresh password/strong MFA and expectedVersion. Secrets are never returned.
// @Tags Auth settings
// @Produce json
// @Accept json
// @Param body body TelegramBotUpdateRequest true "settings"
// @Success 200 {object} TelegramBotResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @ID postAdminAuthSettingsMfaTelegramBot
// @Router /api/v1/admin/auth/settings/mfa/telegram/bot [post]
func (h *TelegramHandler) UpdateBot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := settingshttp.Principal(w, r)
	if !ok {
		return
	}
	var input TelegramBotUpdateRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.UpdateBot(r.Context(), settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: input.ExpectedVersion, BotToken: input.BotToken, RotateWebhookSecret: input.RotateWebhookSecret})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

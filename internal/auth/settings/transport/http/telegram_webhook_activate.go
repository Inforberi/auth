package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Register the project-owned HTTPS Telegram webhook
// @Description Requires current auth.settings.manage. Mutations require fresh password/strong MFA and expectedVersion. Secrets are never returned.
// @Tags Auth settings
// @Produce json
// @Accept json
// @Param body body WebhookActivationRequest true "settings"
// @Success 200 {object} TelegramBotResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/auth/settings/mfa/telegram/webhook [post]
func (h *TelegramHandler) ActivateWebhook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	var input WebhookActivationRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.ActivateWebhook(r.Context(), actor, input.ExpectedVersion)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

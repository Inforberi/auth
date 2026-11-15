package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectWebhookRequest struct {
	ExpectedVersion int64 `json:"expectedVersion"`
} // @name project_http.ProjectWebhookRequest

// @Summary Activate the Telegram webhook for a project
// @Description Requires fresh platform authentication and settings permission. Uses the registered project origin and stored credentials.
// @Tags Platform Projects
// @Accept json
// @Produce json
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Project version"
// @Param expectedGeneration query int true "Project generation"
// @Param body body ProjectWebhookRequest true "Current Telegram bot settings version"
// @Success 200 {object} domain.TelegramBotSnapshot
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsTelegramBotWebhook
// @Router /api/v1/platform/projects/{id}/auth/settings/telegram-bot/webhook [post]
func (h *AuthPolicyHandler) ActivateTelegramWebhook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	var input ProjectWebhookRequest
	if httpx.DecodeJSON(w, r, &input) != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	if h.telegramBot == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	result, err := h.telegramBot.ActivateProjectWebhook(r.Context(), actor, target, input.ExpectedVersion)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

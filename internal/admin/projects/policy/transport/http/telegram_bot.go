package http

import (
	"context"
	"net/http"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	telegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProjectTelegramBot interface {
	ReadProjectBot(context.Context, operators.Principal, domain.DirectoryTarget) (settings.TelegramBotSnapshot, error)
	UpdateProjectBot(context.Context, operators.Principal, domain.DirectoryTarget, telegram.TelegramBotUpdateInput) (settings.TelegramBotSnapshot, error)
	ActivateProjectWebhook(context.Context, operators.Principal, domain.DirectoryTarget, int64) (settings.TelegramBotSnapshot, error)
}

func (h *AuthPolicyHandler) WithProjectTelegramBot(backend ProjectTelegramBot) *AuthPolicyHandler {
	h.telegramBot = backend
	return h
}

type ProjectTelegramBotRequest struct {
	ExpectedVersion     int64   `json:"expectedVersion"`
	BotToken            *string `json:"botToken,omitempty"`
	RotateWebhookSecret bool    `json:"rotateWebhookSecret"`
} // @name project_http.ProjectTelegramBotRequest

// @Summary Read project Telegram bot settings
// @Tags Platform Projects
// @Success 200 {object} settings.TelegramBotSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID getPlatformProjectsByIdAuthSettingsTelegramBot
// @Router /api/v1/platform/projects/{id}/auth/settings/telegram-bot [get]
func (h *AuthPolicyHandler) ReadTelegramBot(w http.ResponseWriter, r *http.Request) {
	h.projectTelegramBot(w, r, false)
}

// @Summary Replace the project Telegram bot token or rotate its webhook secret
// @Tags Platform Projects
// @Param body body ProjectTelegramBotRequest true "Expected version and credential change"
// @Success 200 {object} settings.TelegramBotSnapshot
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Security SessionCookie
// @ID postPlatformProjectsByIdAuthSettingsTelegramBot
// @Router /api/v1/platform/projects/{id}/auth/settings/telegram-bot [post]
func (h *AuthPolicyHandler) UpdateTelegramBot(w http.ResponseWriter, r *http.Request) {
	h.projectTelegramBot(w, r, true)
}

func (h *AuthPolicyHandler) projectTelegramBot(w http.ResponseWriter, r *http.Request, update bool) {
	actor, ok := catalog.RequestActor(w, r)
	if !ok {
		return
	}
	_, target, ok := catalog.DirectoryQuery(w, r)
	if !ok {
		return
	}
	if h.telegramBot == nil {
		h.respondError(w, r, domain.ErrUnavailable)
		return
	}
	var result settings.TelegramBotSnapshot
	var err error
	if update {
		var input ProjectTelegramBotRequest
		if err := httpx.DecodeJSON(w, r, &input); err != nil {
			httpx.Error(w, 400, "invalid_json", "invalid JSON")
			return
		}
		result, err = h.telegramBot.UpdateProjectBot(r.Context(), actor, target, telegram.TelegramBotUpdateInput{
			ExpectedVersion: input.ExpectedVersion, BotToken: input.BotToken, RotateWebhookSecret: input.RotateWebhookSecret,
		})
	} else {
		result, err = h.telegramBot.ReadProjectBot(r.Context(), actor, target)
	}
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, result)
}

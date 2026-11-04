package settingstelegramhttp

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type telegramSettings interface {
	ReadBot(context.Context, accessservice.Principal) (domain.TelegramBotSnapshot, error)
	UpdateBot(context.Context, settingstelegram.TelegramBotUpdateInput) (domain.TelegramBotSnapshot, error)
	ReadPolicy(context.Context, accessservice.Principal) (domain.TelegramMFASnapshot, error)
	UpdatePolicy(context.Context, service.TelegramMFAUpdate) (domain.TelegramMFASnapshot, error)
	ActivateWebhook(context.Context, accessservice.Principal, int64) (domain.TelegramBotSnapshot, error)
}

type TelegramHandler struct {
	service telegramSettings
	log     *zap.Logger
}

func NewTelegram(service telegramSettings, log *zap.Logger) *TelegramHandler {
	return &TelegramHandler{service: service, log: log}
}

var telegramSettingsErrors = append([]httpx.ErrorRule{
	httpx.MatchError(domain.ErrInvalidTelegramBot, 400, "invalid_telegram_bot", "invalid Telegram bot settings"),
	httpx.MatchError(domain.ErrTelegramFactorInUse, 409, "telegram_factor_in_use", "Telegram MFA is configured for users"),
	httpx.MatchError(domain.ErrPolicyConflict, 409, "mfa_policy_conflict", "settings changed; reload and retry"),
	httpx.MatchError(domain.ErrMethodNotReady, 409, "mfa_not_ready", "Telegram capability unavailable"),
	httpx.MatchError(domain.ErrInvalidMFAPolicy, 400, "invalid_mfa_policy", "positive expectedVersion required"),
	{Target: domain.ErrTelegramBotLimited, Response: httpx.Failure{Status: 429, Code: "rate_limited", Message: "rate limited", Headers: http.Header{"Retry-After": {"60"}}}},
}, settingshttp.SettingsErrorRules()...)

func (h *TelegramHandler) respondError(w http.ResponseWriter, r *http.Request, err error) {
	httpx.RespondError(w, r, h.log, "telegram_mfa_settings", err, telegramSettingsErrors, httpx.Failure{Status: 503, Code: "temporarily_unavailable", Message: "temporarily unavailable"})
}

type TelegramBotUpdateRequest struct {
	ExpectedVersion     int64   `json:"expectedVersion"`
	BotToken            *string `json:"botToken"`
	RotateWebhookSecret bool    `json:"rotateWebhookSecret"`
} // @name http.TelegramBotUpdateRequest

type TelegramPolicyRequest struct {
	ExpectedVersion int64 `json:"expectedVersion"`
	Allowed         *bool `json:"allowed"`
} // @name http.TelegramPolicyRequest

type WebhookActivationRequest struct {
	ExpectedVersion int64 `json:"expectedVersion"`
} // @name http.WebhookActivationRequest

type TelegramBotResponse = domain.TelegramBotSnapshot // @name http.TelegramBotResponse

type TelegramPolicyResponse struct {
	Version int64 `json:"version"`
	Allowed bool  `json:"allowed"`
} // @name http.TelegramPolicyResponse

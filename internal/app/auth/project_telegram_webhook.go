package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	telegrambot "github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func (p *projectTelegramMFA) webhookHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
		httpx.Error(w, 403, "invalid_webhook", "invalid webhook")
		return
	}
	cfg := p.manager.factory.managementConfig
	allowed, err := p.manager.factory.limits.AllowAll(r.Context(), []mfaservice.Budget{
		{Key: "telegram-webhook:project", Count: cfg.GlobalLimitPerMinute},
	})
	if err != nil {
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, 429, "rate_limited", "rate limited")
		return
	}
	err = p.manager.use(r.Context(), func(ctx context.Context, pool *pgxpool.Pool) error {
		preparation, credentials, err := p.preparation(ctx, pool)
		if err != nil {
			return err
		}
		bot, err := telegrambot.BotFromSettings(botIdentity(credentials.Snapshot))
		if err != nil {
			return err
		}
		decoder, err := telegrambot.NewWebhook(bot, credentials.WebhookSecret)
		if err != nil {
			return err
		}
		start, err := decoder.DecodeStart(r.Header.Values("X-Telegram-Bot-Api-Secret-Token"), r.Body, time.Now())
		if err != nil {
			return err
		}
		delivery, err := preparation.Receive(ctx, mfatelegram.TelegramStart{BotID: start.BotID, TelegramID: start.UserID, UpdateID: start.UpdateID, Binding: start.Binding})
		if err != nil {
			return err
		}
		token, err := telegrambot.NewCredentials(credentials.Token.Value())
		if err != nil {
			return err
		}
		return p.client.SendCode(ctx, token, delivery.TelegramID, delivery.Code)
	})
	if err == nil || errors.Is(err, telegrambot.ErrIgnored) || errors.Is(err, mfadomain.ErrInvalidTelegramPreparation) {
		w.WriteHeader(204)
		return
	}
	if errors.Is(err, telegrambot.ErrWebhook) {
		httpx.Error(w, 403, "invalid_webhook", "invalid webhook")
		return
	}
	if errors.Is(err, mfadomain.ErrLimited) {
		w.Header().Set("Retry-After", "60")
		httpx.Error(w, 429, "rate_limited", "rate limited")
		return
	}
	httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
}

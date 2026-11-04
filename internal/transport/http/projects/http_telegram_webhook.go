package browser

import (
	"context"
	"errors"
	"net/http"
	"time"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type telegramWebhookService interface {
	AllowTelegramWebhook(context.Context) (bool, error)
	ReceiveTelegramWebhook(context.Context, func(*telegrambot.Webhook) (telegrambot.Start, error)) error
}

func telegramWebhookHandler(service telegramWebhookService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			httpx.Error(w, 403, "invalid_webhook", "invalid webhook")
			return
		}
		allowed, err := service.AllowTelegramWebhook(r.Context())
		if err != nil {
			httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			httpx.Error(w, 429, "rate_limited", "rate limited")
			return
		}
		err = service.ReceiveTelegramWebhook(r.Context(), func(decoder *telegrambot.Webhook) (telegrambot.Start, error) {
			return decoder.DecodeStart(r.Header.Values("X-Telegram-Bot-Api-Secret-Token"), r.Body, time.Now())
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
}

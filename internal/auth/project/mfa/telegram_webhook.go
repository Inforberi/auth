package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

func (p *ProjectTelegramMFA) AllowTelegramWebhook(ctx context.Context) (bool, error) {
	cfg := p.manager.factory.managementConfig
	return p.manager.factory.limits.AllowAll(ctx, []mfaservice.Budget{
		{Key: "telegram-webhook:project", Count: cfg.GlobalLimitPerMinute},
	})
}

// ReceiveTelegramWebhook keeps decoding, receipt and delivery inside one current
// project lease. The transport callback authenticates the webhook before reading
// its body; no credentials or preparation service escape the lease.
func (p *ProjectTelegramMFA) ReceiveTelegramWebhook(ctx context.Context, decode func(*telegrambot.Webhook) (telegrambot.Start, error)) error {
	return p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
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
		start, err := decode(decoder)
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
}

package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	telegrambot "github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

func (p *projectTelegramMFA) ReadBot(ctx context.Context, actor accessservice.Principal) (settingsdomain.TelegramBotSnapshot, error) {
	var result settingsdomain.TelegramBotSnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.settings(pool)
		if err != nil {
			return err
		}
		result, err = service.Read(ctx, actor)
		return err
	})
	return result, err
}

func (p *projectTelegramMFA) UpdateBot(ctx context.Context, input settingsservice.TelegramBotUpdateInput) (settingsdomain.TelegramBotSnapshot, error) {
	var result settingsdomain.TelegramBotSnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.settings(pool)
		if err != nil {
			return err
		}
		result, err = service.Update(ctx, input)
		return err
	})
	return result, err
}

func (p *projectTelegramMFA) ReadPolicy(ctx context.Context, actor accessservice.Principal) (settingsdomain.TelegramMFASnapshot, error) {
	var result settingsdomain.TelegramMFASnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		var err error
		result, err = settingsservice.NewTelegramMFA(settingspostgres.New(pool), true).Read(ctx, actor)
		return err
	})
	return result, err
}

func (p *projectTelegramMFA) UpdatePolicy(ctx context.Context, input settingsservice.TelegramMFAUpdate) (settingsdomain.TelegramMFASnapshot, error) {
	var result settingsdomain.TelegramMFASnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		_, credentialErr := p.credentials(ctx, pool)
		ready := p.profile.deliveryReady() && credentialErr == nil
		var err error
		result, err = settingsservice.NewTelegramMFA(settingspostgres.New(pool), ready).Update(ctx, input)
		return err
	})
	return result, err
}

func (p *projectTelegramMFA) ActivateWebhook(ctx context.Context, actor accessservice.Principal, version int64) (settingsdomain.TelegramBotSnapshot, error) {
	var result settingsdomain.TelegramBotSnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.settings(pool)
		if err != nil {
			return err
		}
		result, err = service.ActivateWebhook(ctx, actor, version, func(ctx context.Context, credentials settingsservice.TelegramBotCredentials) error {
			token, err := telegrambot.NewCredentials(credentials.Token.Value())
			if err != nil {
				return err
			}
			return p.client.SetWebhook(ctx, token, p.profile.origin+"/api/v1/auth/mfa/telegram/webhook", credentials.WebhookSecret)
		})
		return err
	})
	return result, err
}

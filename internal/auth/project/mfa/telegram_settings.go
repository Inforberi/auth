package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

func (p *ProjectTelegramMFA) ReadBot(ctx context.Context, actor accessservice.Principal) (settingsdomain.TelegramBotSnapshot, error) {
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

func (p *ProjectTelegramMFA) UpdateBot(ctx context.Context, input settingstelegram.TelegramBotUpdateInput) (settingsdomain.TelegramBotSnapshot, error) {
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

func (p *ProjectTelegramMFA) ReadPolicy(ctx context.Context, actor accessservice.Principal) (settingsdomain.TelegramMFASnapshot, error) {
	var result settingsdomain.TelegramMFASnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		var err error
		result, err = settingsservice.NewTelegramMFA(settingspostgres.New(pool), true).Read(ctx, actor)
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) UpdatePolicy(ctx context.Context, input settingsservice.TelegramMFAUpdate) (settingsdomain.TelegramMFASnapshot, error) {
	var result settingsdomain.TelegramMFASnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		_, credentialErr := p.credentials(ctx, pool)
		ready := p.deliveryReady() && credentialErr == nil
		var err error
		result, err = settingsservice.NewTelegramMFA(settingspostgres.New(pool), ready).Update(ctx, input)
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) ActivateWebhook(ctx context.Context, actor accessservice.Principal, version int64) (settingsdomain.TelegramBotSnapshot, error) {
	var result settingsdomain.TelegramBotSnapshot
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.settings(pool)
		if err != nil {
			return err
		}
		result, err = service.ActivateWebhook(ctx, actor, version, p.registerWebhook)
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) PreparePlatformBot(ctx context.Context, actor account.UserID, input settingstelegram.TelegramBotUpdateInput, before settingstelegram.TelegramBotStored) (settingstelegram.TelegramBotUpdate, error) {
	service, err := p.botPreparation()
	if err != nil {
		return settingstelegram.TelegramBotUpdate{}, err
	}
	input.Actor.UserID = actor
	return service.PrepareUpdate(ctx, input, before)
}

func (p *ProjectTelegramMFA) RegisterPlatformWebhook(ctx context.Context, actor account.UserID, version int64, stored settingstelegram.TelegramBotStored) error {
	service, err := p.botPreparation()
	if err != nil {
		return err
	}
	return service.RegisterWebhook(ctx, actor, version, stored, p.registerWebhook)
}

func (p *ProjectTelegramMFA) botPreparation() (*settingstelegram.TelegramBotSettings, error) {
	cfg := p.manager.factory.managementConfig
	return settingstelegram.NewTelegramBotPreparation(p.token, p.webhook, p.client, p.manager.factory.limits, tokengenerate.New(), settingstelegram.TelegramBotLimits{
		UserUpdatesPerMinute: cfg.UserLimitPerMinute, ProjectUpdatesPerMinute: cfg.GlobalLimitPerMinute,
	})
}

func (p *ProjectTelegramMFA) registerWebhook(ctx context.Context, credentials settingstelegram.TelegramBotCredentials) error {
	token, err := telegrambot.NewCredentials(credentials.Token.Value())
	if err != nil {
		return err
	}
	return p.client.SetWebhook(ctx, token, p.origin+"/api/v1/auth/mfa/telegram/webhook", credentials.WebhookSecret)
}

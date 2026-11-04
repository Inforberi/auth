package mfa

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

func (p *ProjectTelegramMFA) Request(ctx context.Context, proof mfaservice.Proof, ip string) (*mfatelegram.TelegramStarted, error) {
	var result *mfatelegram.TelegramStarted
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		preparation, credentials, err := p.preparation(ctx, pool)
		if err != nil {
			return err
		}
		intent, err := preparation.Request(ctx, proof, ip)
		if err != nil {
			return err
		}
		bot, err := telegrambot.BotFromSettings(botIdentity(credentials.Snapshot))
		if err != nil {
			return err
		}
		link, err := bot.StartURL(intent.Binding)
		result = &mfatelegram.TelegramStarted{Binding: intent.Binding, URL: link, ExpiresAt: intent.ExpiresAt}
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) Confirm(ctx context.Context, input mfatelegram.ConfirmTelegramChannel) (*mfatelegram.TelegramPrepared, error) {
	var result *mfatelegram.TelegramPrepared
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		preparation, _, err := p.preparation(ctx, pool)
		if err != nil {
			return err
		}
		result, err = preparation.Confirm(ctx, input)
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) change(ctx context.Context, proof mfaservice.Proof, enable bool) error {
	return p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		service, err := p.factors(ctx, pool)
		if err != nil {
			return err
		}
		if enable {
			return service.Enable(ctx, proof)
		}
		return service.Disable(ctx, proof)
	})
}

func (p *ProjectTelegramMFA) Status(ctx context.Context, proof mfaservice.Proof) (*domain.TelegramFactor, error) {
	var result *domain.TelegramFactor
	err := p.manager.use(ctx, func(ctx context.Context, pool *pgxpool.Pool) error {
		var err error
		result, err = mfapostgres.New(pool).ReadTelegramFactor(ctx, proof)
		return err
	})
	return result, err
}

func (p *ProjectTelegramMFA) Enable(ctx context.Context, proof mfaservice.Proof) error {
	return p.change(ctx, proof, true)
}

func (p *ProjectTelegramMFA) Disable(ctx context.Context, proof mfaservice.Proof) error {
	return p.change(ctx, proof, false)
}

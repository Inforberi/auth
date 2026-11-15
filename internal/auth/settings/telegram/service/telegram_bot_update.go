package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	account "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type TelegramBotUpdateInput struct {
	Actor               accessservice.Principal
	ExpectedVersion     int64
	BotToken            *string `json:"-"`
	RotateWebhookSecret bool
}

func (s *TelegramBotSettings) Update(ctx context.Context, input TelegramBotUpdateInput) (domain.TelegramBotSnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.TelegramBotSnapshot{}, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return domain.TelegramBotSnapshot{}, domain.ErrInvalidTelegramBot
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	before, err := s.repo.AuthorizeTelegramBotUpdate(ctx, input.Actor, input.ExpectedVersion)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	if input.BotToken == nil && !input.RotateWebhookSecret {
		return before.TelegramBotSnapshot, nil
	}
	prepared, err := s.PrepareUpdate(ctx, input, before)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	return s.repo.UpdateTelegramBot(ctx, prepared)
}

func (s *TelegramBotSettings) PrepareUpdate(ctx context.Context, input TelegramBotUpdateInput, before TelegramBotStored) (TelegramBotUpdate, error) {
	if err := s.admitTelegramBotUpdate(ctx, input.Actor.UserID); err != nil {
		return TelegramBotUpdate{}, err
	}
	var token domain.TelegramBotToken
	var err error
	if input.BotToken == nil {
		token, err = s.openToken(before)
	} else {
		token, err = domain.NewTelegramBotToken(*input.BotToken)
	}
	if err != nil {
		return TelegramBotUpdate{}, err
	}
	// The preflight transaction is committed; network verification holds no SQL locks.
	identity, err := s.verifier.VerifyTelegramBot(ctx, token)
	if errors.Is(err, domain.ErrInvalidTelegramBot) {
		return TelegramBotUpdate{}, domain.ErrInvalidTelegramBot
	}
	if err != nil || !identity.Valid() || identity.ID != token.ID() {
		return TelegramBotUpdate{}, domain.ErrTelegramBotVerification
	}
	webhook, err := s.telegramWebhookForUpdate(before, identity.ID, input.RotateWebhookSecret)
	if err != nil {
		return TelegramBotUpdate{}, err
	}
	encryptedToken, err := sealTelegramSecret(s.tokenCipher, identity.ID, "bot-token", token.Value())
	if err != nil {
		return TelegramBotUpdate{}, err
	}
	encryptedWebhook, err := sealTelegramSecret(s.webhookCipher, identity.ID, "webhook-secret", webhook)
	if err != nil {
		return TelegramBotUpdate{}, err
	}
	return TelegramBotUpdate{
		Actor: input.Actor, ExpectedVersion: input.ExpectedVersion,
		Identity: identity, Token: encryptedToken, Webhook: encryptedWebhook,
	}, nil
}

func (s *TelegramBotSettings) admitTelegramBotUpdate(ctx context.Context, actor account.UserID) error {
	for _, budget := range []struct {
		key   string
		count int
	}{
		{"telegram-bot-settings:user:" + string(actor), s.config.UserUpdatesPerMinute},
		{"telegram-bot-settings:project", s.config.ProjectUpdatesPerMinute},
	} {
		allowed, err := s.limits.Allow(ctx, budget.key, budget.count, time.Minute)
		if err != nil {
			return domain.ErrTelegramBotVerification
		}
		if !allowed {
			return domain.ErrTelegramBotLimited
		}
	}
	return nil
}

func (s *TelegramBotSettings) telegramWebhookForUpdate(before TelegramBotStored, botID int64, rotate bool) (string, error) {
	if before.BotID == botID && before.WebhookSecretSet && !rotate {
		return s.openWebhook(before)
	}
	secret, err := s.tokens.GenerateToken(32)
	if err != nil || !domain.ValidTelegramWebhookSecret(secret) {
		return "", domain.ErrTelegramBotSecret
	}
	return secret, nil
}

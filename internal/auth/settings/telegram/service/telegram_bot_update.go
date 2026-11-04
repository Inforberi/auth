package service

import (
	"context"
	"errors"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
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
	if err := s.admitTelegramBotUpdate(ctx, input.Actor); err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	var token domain.TelegramBotToken
	if input.BotToken == nil {
		token, err = s.openToken(before)
	} else {
		token, err = domain.NewTelegramBotToken(*input.BotToken)
	}
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	// The preflight transaction is committed; network verification holds no SQL locks.
	identity, err := s.verifier.VerifyTelegramBot(ctx, token)
	if errors.Is(err, domain.ErrInvalidTelegramBot) {
		return domain.TelegramBotSnapshot{}, domain.ErrInvalidTelegramBot
	}
	if err != nil || !identity.Valid() || identity.ID != token.ID() {
		return domain.TelegramBotSnapshot{}, domain.ErrTelegramBotVerification
	}
	webhook, err := s.telegramWebhookForUpdate(before, identity.ID, input.RotateWebhookSecret)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	encryptedToken, err := sealTelegramSecret(s.tokenCipher, identity.ID, "bot-token", token.Value())
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	encryptedWebhook, err := sealTelegramSecret(s.webhookCipher, identity.ID, "webhook-secret", webhook)
	if err != nil {
		return domain.TelegramBotSnapshot{}, err
	}
	return s.repo.UpdateTelegramBot(ctx, TelegramBotUpdate{
		Actor: input.Actor, ExpectedVersion: input.ExpectedVersion,
		Identity: identity, Token: encryptedToken, Webhook: encryptedWebhook,
	})
}

func (s *TelegramBotSettings) admitTelegramBotUpdate(ctx context.Context, actor accessservice.Principal) error {
	for _, budget := range []struct {
		key   string
		count int
	}{
		{"telegram-bot-settings:user:" + string(actor.UserID), s.config.UserUpdatesPerMinute},
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

package telegrambot

import (
	"context"
	"errors"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (c *Client) VerifyTelegramBot(ctx context.Context, token domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
	bot, err := c.Check(ctx, Credentials{token: token.Value(), id: token.ID()})
	if errors.Is(err, ErrCredentials) || errors.Is(err, ErrInvalidInput) {
		return domain.TelegramBotIdentity{}, domain.ErrInvalidTelegramBot
	}
	if err != nil {
		return domain.TelegramBotIdentity{}, domain.ErrTelegramBotVerification
	}
	return domain.TelegramBotIdentity{ID: bot.id, Username: bot.username}, nil
}

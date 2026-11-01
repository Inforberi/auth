package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type telegramSecret struct {
	BotID int64  `json:"botId"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type TelegramBotCredentials struct {
	Snapshot      domain.TelegramBotSnapshot
	Token         domain.TelegramBotToken `json:"-"`
	WebhookSecret string                  `json:"-"`
}

func (TelegramBotCredentials) String() string   { return "[Telegram bot credentials]" }
func (TelegramBotCredentials) GoString() string { return "[Telegram bot credentials]" }

func sealTelegramSecret(cipher ProviderCipher, botID int64, kind, value string) ([]byte, error) {
	plain, err := json.Marshal(telegramSecret{BotID: botID, Kind: kind, Value: value})
	if err != nil {
		return nil, domain.ErrTelegramBotSecret
	}
	defer clear(plain)
	encrypted, err := cipher.Seal(plain)
	if err != nil {
		return nil, domain.ErrTelegramBotSecret
	}
	return encrypted, nil
}

func openTelegramSecret(cipher ProviderCipher, encrypted []byte, botID int64, kind string) (string, error) {
	plain, err := cipher.Open(encrypted)
	if err != nil {
		return "", domain.ErrTelegramBotSecret
	}
	defer clear(plain)
	var secret telegramSecret
	if json.Unmarshal(plain, &secret) != nil || secret.BotID != botID || secret.Kind != kind {
		return "", domain.ErrTelegramBotSecret
	}
	return secret.Value, nil
}

func (s *TelegramBotSettings) openToken(stored TelegramBotStored) (domain.TelegramBotToken, error) {
	if !stored.TokenSet || stored.StoredBotID != stored.BotID {
		return domain.TelegramBotToken{}, domain.ErrMethodNotReady
	}
	raw, err := openTelegramSecret(s.tokenCipher, stored.Token, stored.BotID, "bot-token")
	if err != nil {
		return domain.TelegramBotToken{}, err
	}
	token, err := domain.NewTelegramBotToken(raw)
	if err != nil || token.ID() != stored.BotID {
		return domain.TelegramBotToken{}, domain.ErrTelegramBotSecret
	}
	return token, nil
}

func (s *TelegramBotSettings) openWebhook(stored TelegramBotStored) (string, error) {
	if !stored.WebhookSecretSet || stored.StoredBotID != stored.BotID {
		return "", domain.ErrMethodNotReady
	}
	secret, err := openTelegramSecret(s.webhookCipher, stored.Webhook, stored.BotID, "webhook-secret")
	if err != nil || !domain.ValidTelegramWebhookSecret(secret) {
		return "", domain.ErrTelegramBotSecret
	}
	return secret, nil
}

// Credentials is a trusted per-operation loader, never an administrator HTTP response.
func (s *TelegramBotSettings) Credentials(ctx context.Context) (TelegramBotCredentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadTelegramBot(ctx)
	if err != nil {
		return TelegramBotCredentials{}, err
	}
	token, err := s.openToken(stored)
	if err != nil {
		return TelegramBotCredentials{}, err
	}
	webhook, err := s.openWebhook(stored)
	if err != nil {
		return TelegramBotCredentials{}, err
	}
	return TelegramBotCredentials{Snapshot: stored.TelegramBotSnapshot, Token: token, WebhookSecret: webhook}, nil
}

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestTelegramBotStoredSecretBoundaries(t *testing.T) {
	repo := &botSettingsRepo{stored: TelegramBotStored{TelegramBotSnapshot: domain.TelegramBotSnapshot{Version: 1}}}
	verify := botVerifierFunc(func(_ context.Context, token domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
		return domain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	svc := botSettingsService(t, repo, &smtpLimit{allowed: true}, "telegram-bot:project-a", verify)
	_, err := svc.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrMethodNotReady)
	token := botSettingsToken
	_, err = svc.Update(t.Context(), TelegramBotUpdateInput{Actor: smtpActor, ExpectedVersion: 1, BotToken: &token})
	require.NoError(t, err)
	foreign := botSettingsService(t, repo, &smtpLimit{allowed: true}, "telegram-bot:project-b", verify)
	_, err = foreign.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrTelegramBotSecret)
	saved := repo.stored
	repo.stored.Token, repo.stored.Webhook = saved.Webhook, saved.Token
	_, err = svc.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrTelegramBotSecret)
	repo.stored = saved
	repo.stored.BotID, repo.stored.StoredBotID = 987654321, 987654321
	_, err = svc.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrTelegramBotSecret, "ciphertext must bind the expected bot identity")
	repo.stored = saved
	repo.stored.Token = append([]byte(nil), saved.Token...)
	repo.stored.Token[0] ^= 1
	_, err = svc.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrTelegramBotSecret)
}

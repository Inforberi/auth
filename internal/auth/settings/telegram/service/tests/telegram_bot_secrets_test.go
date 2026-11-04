package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

func TestTelegramBotStoredSecretBoundaries(t *testing.T) {
	repo := &botSettingsRepo{stored: settingstelegram.TelegramBotStored{TelegramBotSnapshot: domain.TelegramBotSnapshot{Version: 1}}}
	verify := botVerifierFunc(func(_ context.Context, token domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
		return domain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	svc := botSettingsService(t, repo, &botLimiter{allowed: true}, "telegram-bot:project-a", verify)
	_, err := svc.Credentials(t.Context())
	require.ErrorIs(t, err, domain.ErrMethodNotReady)
	token := botSettingsToken
	_, err = svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 1, BotToken: &token})
	require.NoError(t, err)
	foreign := botSettingsService(t, repo, &botLimiter{allowed: true}, "telegram-bot:project-b", verify)
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

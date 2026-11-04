package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

const botSettingsToken = "123456789:abcdefghijklmnopqrstuvwxyz_0123456789"

type botSettingsRepo struct {
	stored  settingstelegram.TelegramBotStored
	err     error
	checked bool
	saves   int
}

func (r *botSettingsRepo) ReadTelegramBot(context.Context, accessservice.Principal) (domain.TelegramBotSnapshot, error) {
	return r.stored.TelegramBotSnapshot, r.err
}

func (r *botSettingsRepo) LoadTelegramBot(context.Context) (settingstelegram.TelegramBotStored, error) {
	return r.stored, r.err
}

func (r *botSettingsRepo) AuthorizeTelegramBotUpdate(context.Context, accessservice.Principal, int64) (settingstelegram.TelegramBotStored, error) {
	r.checked = true
	return r.stored, r.err
}

func (r *botSettingsRepo) UpdateTelegramBot(_ context.Context, input settingstelegram.TelegramBotUpdate) (domain.TelegramBotSnapshot, error) {
	r.saves++
	r.stored = settingstelegram.TelegramBotStored{TelegramBotSnapshot: domain.TelegramBotSnapshot{
		Version: input.ExpectedVersion + 1, BotID: input.Identity.ID, Username: input.Identity.Username, TokenSet: true, WebhookSecretSet: true,
	}, Token: input.Token, Webhook: input.Webhook, StoredBotID: input.Identity.ID}
	return r.stored.TelegramBotSnapshot, r.err
}

type botVerifierFunc func(context.Context, domain.TelegramBotToken) (domain.TelegramBotIdentity, error)

func (f botVerifierFunc) VerifyTelegramBot(ctx context.Context, token domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
	return f(ctx, token)
}

func botSettingsService(t *testing.T, repo *botSettingsRepo, limits *botLimiter, purpose string, verify botVerifierFunc) *settingstelegram.TelegramBotSettings {
	t.Helper()
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	token, err := secretbox.NewScoped(root, purpose+":token")
	require.NoError(t, err)
	webhook, err := secretbox.NewScoped(root, purpose+":webhook")
	require.NoError(t, err)
	svc, err := settingstelegram.NewTelegramBotSettings(repo, token, webhook, verify, limits, tokengenerate.New(), settingstelegram.TelegramBotLimits{UserUpdatesPerMinute: 3, ProjectUpdatesPerMinute: 10})
	require.NoError(t, err)
	return svc
}

func TestTelegramBotSettingsSecretsAndRotation(t *testing.T) {
	repo := &botSettingsRepo{stored: settingstelegram.TelegramBotStored{TelegramBotSnapshot: domain.TelegramBotSnapshot{Version: 1}}}
	verifications := 0
	verify := botVerifierFunc(func(_ context.Context, token domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
		require.True(t, repo.checked, "actor authorization must precede provider I/O")
		verifications++
		return domain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	svc := botSettingsService(t, repo, &botLimiter{allowed: true}, "telegram-bot:project-a", verify)
	token := botSettingsToken
	input := settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 1, BotToken: &token}
	snapshot, err := svc.Update(t.Context(), input)
	require.NoError(t, err)
	require.EqualValues(t, 2, snapshot.Version)
	require.True(t, snapshot.TokenSet && snapshot.WebhookSecretSet)
	require.NotContains(t, string(repo.stored.Token), token)
	credentials, err := svc.Credentials(t.Context())
	require.NoError(t, err)
	require.Equal(t, token, credentials.Token.Value())
	require.True(t, domain.ValidTelegramWebhookSecret(credentials.WebhookSecret))
	encoded, err := json.Marshal(credentials)
	require.NoError(t, err)
	for _, text := range []string{string(encoded), fmt.Sprintf("%+v %#v", credentials, credentials), fmt.Sprintf("%+v %#v", credentials.Token, credentials.Token)} {
		require.NotContains(t, text, token)
		require.NotContains(t, text, credentials.WebhookSecret)
	}
	_, err = svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 2})
	require.NoError(t, err)
	require.Equal(t, 1, repo.saves, "no-op must not write or contact Telegram")
	require.Equal(t, 1, verifications)
	rotated := strings.Replace(token, "abcdefgh", "ABCDEFGH", 1)
	_, err = svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 2, BotToken: &rotated})
	require.NoError(t, err)
	sameBot, err := svc.Credentials(t.Context())
	require.NoError(t, err)
	require.Equal(t, credentials.WebhookSecret, sameBot.WebhookSecret)
	_, err = svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 3, RotateWebhookSecret: true})
	require.NoError(t, err)
	newSecret, err := svc.Credentials(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, sameBot.WebhookSecret, newSecret.WebhookSecret)
	otherBot := strings.Replace(token, "123456789:", "987654321:", 1)
	_, err = svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 4, BotToken: &otherBot})
	require.NoError(t, err)
	other, err := svc.Credentials(t.Context())
	require.NoError(t, err)
	require.NotEqual(t, newSecret.WebhookSecret, other.WebhookSecret, "changing bot identity must rotate its webhook secret")
}

func TestTelegramBotSettingsAdmissionAndSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authErr  error
		allowed  bool
		limitErr error
		want     error
	}{
		{"permission", accessdomain.ErrForbidden, true, nil, accessdomain.ErrForbidden},
		{"version", domain.ErrPolicyConflict, true, nil, domain.ErrPolicyConflict},
		{"limit", nil, false, nil, domain.ErrTelegramBotLimited},
		{"redis", nil, true, errors.New("private Redis error"), domain.ErrTelegramBotVerification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &botSettingsRepo{err: tc.authErr}
			called := false
			svc := botSettingsService(t, repo, &botLimiter{allowed: tc.allowed, err: tc.limitErr}, "telegram-bot:test", func(context.Context, domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
				called = true
				return domain.TelegramBotIdentity{}, nil
			})
			token := botSettingsToken
			_, err := svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 1, BotToken: &token})
			require.ErrorIs(t, err, tc.want)
			require.False(t, called)
			require.Zero(t, repo.saves)
		})
	}
	repo := &botSettingsRepo{}
	svc := botSettingsService(t, repo, &botLimiter{allowed: true}, "telegram-bot:test", func(context.Context, domain.TelegramBotToken) (domain.TelegramBotIdentity, error) {
		return domain.TelegramBotIdentity{}, errors.New("https://api.telegram.org/bot" + botSettingsToken + "/getMe")
	})
	token := botSettingsToken
	_, err := svc.Update(t.Context(), settingstelegram.TelegramBotUpdateInput{Actor: testActor, ExpectedVersion: 1, BotToken: &token})
	require.ErrorIs(t, err, domain.ErrTelegramBotVerification)
	require.NotContains(t, err.Error(), token)
	require.Zero(t, repo.saves)
}

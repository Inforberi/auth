package auth_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

func TestTelegramBotSettingsSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	var hook func(context.Context)
	var calls atomic.Int32
	verify := telegramBotVerifier(func(ctx context.Context, token settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error) {
		calls.Add(1)
		if hook != nil {
			hook(ctx)
		}
		if err := ctx.Err(); err != nil {
			return settingsdomain.TelegramBotIdentity{}, err
		}
		return settingsdomain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	svc, actor := telegramBotSettingsFixture(t, db, ctx, verify)
	before, err := svc.Read(ctx, actor)
	require.NoError(t, err)
	require.False(t, before.TokenSet || before.WebhookSecretSet)
	_, err = svc.Credentials(ctx)
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	token := settingsBotToken
	hook = func(ctx context.Context) { requireBotVerificationUnlocked(t, db, ctx, actor) }
	configured, err := svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: before.Version, BotToken: &token})
	require.NoError(t, err)
	hook = nil
	require.Equal(t, before.Version+1, configured.Version)
	credentials, err := svc.Credentials(ctx)
	require.NoError(t, err)
	require.Equal(t, token, credentials.Token.Value())
	require.True(t, settingsdomain.ValidTelegramWebhookSecret(credentials.WebhookSecret))
	_, err = svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: configured.Version})
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load(), "no-op must neither verify nor write")
	unauthorized := accessPrincipal(t, db, ctx)
	_, err = svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: unauthorized, ExpectedVersion: configured.Version, BotToken: &token})
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	require.EqualValues(t, 1, calls.Load())
	_, err = svc.Read(ctx, unauthorized)
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	_, err = svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: before.Version, BotToken: &token})
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
	require.EqualValues(t, 1, calls.Load())
	t.Run("rotation invalidates pending preparation without purging it", func(t *testing.T) {
		f := newTelegramPreparationFixture(t, db, ctx, "settings-rotation", false)
		_, confirmation := f.begin(t, ctx)
		rotated := strings.Replace(token, "abcdefgh", "ABCDEFGH", 1)
		_, err := svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: configured.Version, BotToken: &rotated})
		require.NoError(t, err)
		_, err = f.channel.Confirm(ctx, confirmation)
		require.ErrorIs(t, err, mfadomain.ErrUnavailable)
		current, err := svc.Credentials(ctx)
		require.NoError(t, err)
		require.Equal(t, credentials.WebhookSecret, current.WebhookSecret)
		require.Equal(t, rotated, current.Token.Value())
	})
	t.Run("audit failure rolls back metadata and secrets", func(t *testing.T) {
		current, err := svc.Credentials(ctx)
		require.NoError(t, err)
		accessExec(t, db, ctx, `ALTER TABLE auth.telegram_bot_settings_audit ADD CONSTRAINT reject_bot_rotation CHECK(version<1) NOT VALID`)
		t.Cleanup(func() {
			accessExec(t, db, ctx, `ALTER TABLE auth.telegram_bot_settings_audit DROP CONSTRAINT IF EXISTS reject_bot_rotation`)
		})
		_, err = svc.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: current.Snapshot.Version, RotateWebhookSecret: true})
		require.Error(t, err)
		after, err := svc.Credentials(ctx)
		require.NoError(t, err)
		require.Equal(t, current.Snapshot, after.Snapshot)
		require.Equal(t, current.Token.Value(), after.Token.Value())
		require.Equal(t, current.WebhookSecret, after.WebhookSecret)
	})
	checkTelegramBotSettingsRaces(t, db, ctx, svc, actor, &hook)
	var audit string
	require.NoError(t, db.QueryRow(ctx, `SELECT COALESCE(string_agg(previous_configuration::text||next_configuration::text,''),'') FROM auth.telegram_bot_settings_audit`).Scan(&audit))
	require.NotContains(t, audit, token)
	require.NotContains(t, audit, credentials.WebhookSecret)
	var providers int
	require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.provider_settings`).Scan(&providers))
	require.Zero(t, providers, "Bot API settings must not overwrite OIDC credentials")
}

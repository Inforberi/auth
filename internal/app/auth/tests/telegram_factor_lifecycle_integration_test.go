package auth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
)

func TestTelegramFactorLifecycleSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	verify := telegramBotVerifier(func(_ context.Context, token settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error) {
		return settingsdomain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	bot, actor := telegramBotSettingsFixture(t, db, ctx, verify)
	initial, err := bot.Read(ctx, actor)
	require.NoError(t, err)
	policy := settingsservice.NewTelegramMFA(settingspostgres.New(db), true)
	_, err = policy.Update(ctx, settingsservice.TelegramMFAUpdate{Actor: actor, ExpectedVersion: initial.Version, Allowed: true})
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady, "configuration needs bot credentials")
	token := settingsBotToken
	configured, err := bot.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: initial.Version, BotToken: &token})
	require.NoError(t, err)
	change := settingsservice.TelegramMFAUpdate{Actor: actor, ExpectedVersion: configured.Version, Allowed: true}
	_, err = settingsservice.NewTelegramMFA(settingspostgres.New(db), false).Update(ctx, change)
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	_, err = policy.Read(ctx, accessPrincipal(t, db, ctx))
	require.ErrorIs(t, err, accessdomain.ErrForbidden)
	current, err := policy.Update(ctx, change)
	require.NoError(t, err)
	require.True(t, current.Allowed)
	_, err = policy.Update(ctx, change)
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
	require.Error(t, mfapostgres.New(db).CheckEmailCapability(ctx, true, true), "private lifecycle is not a Telegram login runtime")

	t.Run("enable replace disable revokes credentials", func(t *testing.T) {
		f, svc := telegramFactorFixture(t, db, ctx, "lifecycle", true)
		other := f.cloneSession(t, db, ctx, "browser")
		confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
		require.NoError(t, svc.Enable(ctx, f.proof))
		for _, hash := range []string{f.proof.TokenHash, other.TokenHash} {
			_, err := f.sessions.FindSession(ctx, hash)
			require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
		}
		f.proof = renewedEmailFactorProof(t, db, ctx, f.user)
		state, err := svc.Status(ctx, f.proof)
		require.NoError(t, err)
		require.True(t, state.Configured && state.Allowed)
		require.EqualValues(t, 1<<40, state.TelegramID)
		_, err = policy.Update(ctx, settingsservice.TelegramMFAUpdate{Actor: actor, ExpectedVersion: current.Version, Allowed: false})
		require.ErrorIs(t, err, settingsdomain.ErrTelegramFactorInUse)
		otherToken := strings.Replace(token, "123456789", "987654321", 1)
		_, err = bot.Update(ctx, settingstelegram.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: current.Version, BotToken: &otherToken})
		require.ErrorIs(t, err, settingsdomain.ErrTelegramFactorInUse)

		confirmTelegramFactorChannel(t, ctx, &f, 1<<40+1)
		require.NoError(t, svc.Enable(ctx, f.proof))
		f.proof = renewedEmailFactorProof(t, db, ctx, f.user)
		state, err = svc.Status(ctx, f.proof)
		require.NoError(t, err)
		require.EqualValues(t, 1<<40+1, state.TelegramID)
		require.NoError(t, svc.Disable(ctx, f.proof))
		_, err = f.sessions.FindSession(ctx, f.proof.TokenHash)
		require.ErrorIs(t, err, sessiondomain.ErrSessionNotFound)
		var pending int
		require.NoError(t, db.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_telegram_preparations WHERE user_id=$1`, f.user).Scan(&pending))
		require.Zero(t, pending)
	})
	checkTelegramLifecycleGuards(t, db, ctx, current.Version)
}

package auth_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

const settingsBotToken = "123456789:abcdefghijklmnopqrstuvwxyz_0123456789"

type telegramBotVerifier func(context.Context, settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error)

func (f telegramBotVerifier) VerifyTelegramBot(ctx context.Context, token settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error) {
	return f(ctx, token)
}

func telegramBotSettingsFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, verify telegramBotVerifier) (*settingstelegram.TelegramBotSettings, accessservice.Principal) {
	t.Helper()
	actor := accessPrincipal(t, db, ctx)
	accessExec(t, db, ctx, `WITH role AS(INSERT INTO auth.roles(key,name) VALUES('telegram_bot_manager','Bot manager') RETURNING id),
 permissions AS(INSERT INTO auth.role_permissions(role_id,permission_key) SELECT id,'auth.settings.manage' FROM role)
 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM role`, actor.UserID)
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	token, err := secretbox.NewScoped(root, "telegram-bot-token:project-a:v1")
	require.NoError(t, err)
	webhook, err := secretbox.NewScoped(root, "telegram-webhook:project-a:v1")
	require.NoError(t, err)
	svc, err := settingstelegram.NewTelegramBotSettings(settingspostgres.New(db), token, webhook, verify, mfaTestLimit{}, tokengenerate.New(), settingstelegram.TelegramBotLimits{
		UserUpdatesPerMinute: 100, ProjectUpdatesPerMinute: 1000,
	})
	require.NoError(t, err)
	return svc, actor
}

func requireBotVerificationUnlocked(t *testing.T, db *pgxpool.Pool, ctx context.Context, actor accessservice.Principal) {
	t.Helper()
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		require.NoError(t, tx.Rollback(cleanup))
	}()
	var unlocked bool
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(734013981)`).Scan(&unlocked))
	require.True(t, unlocked)
	_, err = tx.Exec(ctx, `SELECT singleton FROM auth.mfa_settings FOR UPDATE NOWAIT`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT id FROM auth.users WHERE id=$1 FOR UPDATE NOWAIT`, actor.UserID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT id FROM auth.sessions WHERE token_hash=$1 FOR UPDATE NOWAIT`, actor.TokenHash)
	require.NoError(t, err)
}

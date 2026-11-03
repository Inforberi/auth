package auth_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

var telegramFactorUpdates atomic.Int64

func telegramFactorFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string, strong bool) (telegramPreparationFixture, *mfatelegram.TelegramFactors) {
	t.Helper()
	f := newTelegramPreparationFixture(t, db, ctx, name, strong)
	svc, err := mfatelegram.NewTelegramFactors(mfapostgres.New(db), f.cipher, mfaTestLimit{}, mfatelegram.TelegramFactorConfig{
		Bot: f.config.Bot, UserMutationsPerMinute: 100, ProjectMutationsPerMinute: 1000,
	})
	require.NoError(t, err)
	t.Cleanup(func() { accessExec(t, db, ctx, `DELETE FROM auth.mfa_telegram WHERE user_id=$1`, f.user) })
	return f, svc
}

func confirmTelegramFactorChannel(t *testing.T, ctx context.Context, f *telegramPreparationFixture, telegramID int64) {
	t.Helper()
	start, err := f.channel.Request(ctx, f.proof, "192.0.2.1")
	require.NoError(t, err)
	delivery, err := f.channel.Receive(ctx, mfatelegram.TelegramStart{BotID: f.config.Bot.ID, TelegramID: telegramID, UpdateID: 1<<32 + telegramFactorUpdates.Add(1), Binding: start.Binding})
	require.NoError(t, err)
	confirmed, err := f.channel.Confirm(ctx, mfatelegram.ConfirmTelegramChannel{Proof: f.proof, Binding: start.Binding, Code: delivery.Code, IP: "192.0.2.1"})
	require.NoError(t, err)
	f.proof.TokenHash = tokengenerate.New().Hash(confirmed.Token)
}

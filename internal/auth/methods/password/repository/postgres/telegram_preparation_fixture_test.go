package postgres

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type telegramPreparationFixture struct {
	emailPreparationSQLFixture
	channel *mfaservice.TelegramPreparation
	config  mfaservice.TelegramPreparationConfig
}

func newTelegramPreparationFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string, strong bool) telegramPreparationFixture {
	t.Helper()
	base := newEmailPreparationFixture(t, db, ctx, "telegram-"+tokengenerate.New().Hash(name)[:16], strong)
	var version int64
	require.NoError(t, db.QueryRow(ctx, `UPDATE auth.mfa_settings SET telegram_bot_id=123456789 RETURNING version`).Scan(&version))
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "telegram-channel:test:"+tokengenerate.New().Hash(name))
	require.NoError(t, err)
	cfg := mfaservice.TelegramPreparationConfig{
		Bot:                    mfadomain.TelegramBotBinding{ID: 123456789, PolicyVersion: version},
		TTL:                    3 * time.Minute,
		RequestsPerMinute:      100,
		UpdatesPerMinute:       500,
		ConfirmationsPerMinute: 1000,
	}
	svc, err := mfaservice.NewTelegramPreparation(mfapostgres.New(db), cipher, mfaTestLimit{}, tokengenerate.New(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		accessExec(t, db, cleanup, `DELETE FROM auth.mfa_telegram_preparations WHERE user_id=$1`, base.user)
		accessExec(t, db, cleanup, `DELETE FROM auth.mfa_audit WHERE user_id=$1`, base.user)
	})
	return telegramPreparationFixture{emailPreparationSQLFixture: base, channel: svc, config: cfg}
}

func (f telegramPreparationFixture) begin(t *testing.T, ctx context.Context) (mfaservice.TelegramStart, mfaservice.ConfirmTelegramChannel) {
	t.Helper()
	start, err := f.channel.Request(ctx, f.proof, "192.0.2.1")
	require.NoError(t, err)
	input := mfaservice.TelegramStart{BotID: f.config.Bot.ID, TelegramID: 1 << 40, UpdateID: 1, Binding: start.Binding}
	delivery, err := f.channel.Receive(ctx, input)
	require.NoError(t, err)
	return input, mfaservice.ConfirmTelegramChannel{Proof: f.proof, Binding: start.Binding, Code: delivery.Code, IP: "192.0.2.1"}
}

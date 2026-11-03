package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/totp"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type telegramSQLSender struct {
	code  string
	fail  error
	after func(context.Context)
}

func (s *telegramSQLSender) SendLoginCode(ctx context.Context, _ mfalogin.TelegramLoginChannel, code string) error {
	s.code = code
	if s.after != nil {
		s.after(ctx)
	}
	return s.fail
}

type telegramLoginSQLFixture struct {
	telegramPreparationFixture
	primary  mfaservice.PrimaryProof
	login    *mfalogin.Login
	telegram *mfalogin.TelegramLogin
	selector *mfalogin.Selector
	sender   *telegramSQLSender
}

func configureTelegramLoginFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context) {
	t.Helper()
	verify := telegramBotVerifier(func(_ context.Context, token settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error) {
		return settingsdomain.TelegramBotIdentity{ID: token.ID(), Username: "SecurityBot"}, nil
	})
	bot, actor := telegramBotSettingsFixture(t, db, ctx, verify)
	saved, err := bot.Read(ctx, actor)
	require.NoError(t, err)
	token := settingsBotToken
	_, err = bot.Update(ctx, settingsservice.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: saved.Version, BotToken: &token})
	require.NoError(t, err)
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET telegram_factor_allowed=true`)
}

func newTelegramLoginSQLFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, name string) telegramLoginSQLFixture {
	t.Helper()
	f, factors := telegramFactorFixture(t, db, ctx, name, false)
	confirmTelegramFactorChannel(t, ctx, &f, 1<<40)
	require.NoError(t, factors.Enable(ctx, f.proof))
	repo := mfapostgres.New(db)
	cipher := recoveryCipher(t)
	login, err := mfalogin.NewLogin(repo, cipher, totp.Authenticator{}, mfaTestLimit{}, tokengenerate.New(), emailFactorLoginConfig())
	require.NoError(t, err)
	sender := &telegramSQLSender{}
	telegram, err := mfalogin.NewTelegramLogin(repo, cipher, mfaTestLimit{}, tokengenerate.New(), sender, emailFactorLoginConfig())
	require.NoError(t, err)
	return telegramLoginSQLFixture{telegramPreparationFixture: f, primary: mfaservice.PrimaryProof{UserID: f.user, AuthVersion: f.proof.AuthVersion + 1, Method: "password", Reference: "old-hash", VerifiedAt: time.Now().UTC()}, login: login, telegram: telegram, selector: mfalogin.NewSelector(login, repo, nil, telegram), sender: sender}
}

func (f telegramLoginSQLFixture) start(t *testing.T, ctx context.Context) mfalogin.CompleteLoginInput {
	t.Helper()
	challenge, err := f.selector.Start(ctx, f.primary, "192.0.2.1")
	require.NoError(t, err)
	require.Equal(t, mfadomain.TelegramCode, challenge.Method)
	return mfalogin.CompleteLoginInput{Token: challenge.Token, Binding: challenge.Binding, Code: f.sender.code, IP: "192.0.2.1"}
}

package mfa

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfatelegram "github.com/Inforberi/financial-intelligence/internal/auth/mfa/telegram/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingstelegram "github.com/Inforberi/financial-intelligence/internal/auth/settings/telegram/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	"github.com/Inforberi/financial-intelligence/internal/integrations/telegram/bot"
)

type ProjectTelegramClient interface {
	VerifyTelegramBot(context.Context, settingsdomain.TelegramBotToken) (settingsdomain.TelegramBotIdentity, error)
	SendCode(context.Context, telegrambot.Credentials, int64, string) error
	SetWebhook(context.Context, telegrambot.Credentials, string, string) error
}

type ProjectTelegramMFA struct {
	origin                  string
	deliveryReady           func() bool
	manager                 *ProjectMFA
	client                  ProjectTelegramClient
	token, webhook, channel *secretbox.Cipher
}

func (p *ProjectTelegramMFA) settings(pool *pgxpool.Pool) (*settingstelegram.TelegramBotSettings, error) {
	cfg := p.manager.factory.managementConfig
	return settingstelegram.NewTelegramBotSettings(settingspostgres.New(pool), p.token, p.webhook, p.client, p.manager.factory.limits, tokengenerate.New(), settingstelegram.TelegramBotLimits{
		UserUpdatesPerMinute: cfg.UserLimitPerMinute, ProjectUpdatesPerMinute: cfg.GlobalLimitPerMinute,
	})
}

func (p *ProjectTelegramMFA) credentials(ctx context.Context, pool *pgxpool.Pool) (settingstelegram.TelegramBotCredentials, error) {
	settings, err := p.settings(pool)
	if err != nil {
		return settingstelegram.TelegramBotCredentials{}, err
	}
	return settings.Credentials(ctx)
}

func (p *ProjectTelegramMFA) preparation(ctx context.Context, pool *pgxpool.Pool) (*mfatelegram.TelegramPreparation, settingstelegram.TelegramBotCredentials, error) {
	credentials, err := p.credentials(ctx, pool)
	if err != nil {
		return nil, credentials, err
	}
	cfg := p.manager.factory.managementConfig
	service, err := mfatelegram.NewTelegramPreparation(mfapostgres.New(pool), p.channel, p.manager.factory.limits, tokengenerate.New(), mfatelegram.TelegramPreparationConfig{
		Bot: mfadomain.TelegramBotBinding{ID: credentials.Snapshot.BotID, PolicyVersion: credentials.Snapshot.Version},
		TTL: cfg.ChallengeTTL, RequestsPerMinute: cfg.GlobalLimitPerMinute, UpdatesPerMinute: cfg.GlobalLimitPerMinute, ConfirmationsPerMinute: cfg.GlobalLimitPerMinute, UserLimitPerMinute: cfg.UserLimitPerMinute, IPLimitPerMinute: cfg.IPLimitPerMinute,
	})
	return service, credentials, err
}

func (p *ProjectTelegramMFA) factors(ctx context.Context, pool *pgxpool.Pool) (*mfatelegram.TelegramFactors, error) {
	credentials, err := p.credentials(ctx, pool)
	if err != nil {
		return nil, err
	}
	cfg := p.manager.factory.managementConfig
	return mfatelegram.NewTelegramFactors(mfapostgres.New(pool), p.manager.factory.cipher, p.manager.factory.limits, mfatelegram.TelegramFactorConfig{
		Bot:                    mfadomain.TelegramBotBinding{ID: credentials.Snapshot.BotID, PolicyVersion: credentials.Snapshot.Version},
		UserMutationsPerMinute: cfg.UserLimitPerMinute, ProjectMutationsPerMinute: cfg.GlobalLimitPerMinute,
	})
}

func (p *ProjectTelegramMFA) Login(pool *pgxpool.Pool, factory *ProjectMFALogin) (*mfalogin.TelegramLogin, error) {
	return mfalogin.NewTelegramLogin(mfapostgres.New(pool), factory.cipher, factory.limits, tokengenerate.New(), projectTelegramSender{owner: p, pool: pool}, factory.config)
}

type projectTelegramSender struct {
	owner *ProjectTelegramMFA
	pool  *pgxpool.Pool
}

func (s projectTelegramSender) SendLoginCode(ctx context.Context, channel mfalogin.TelegramLoginChannel, code string) error {
	credentials, err := s.owner.credentials(ctx, s.pool)
	if err != nil {
		return err
	}
	if credentials.Snapshot.BotID != channel.Bot.ID || credentials.Snapshot.Version != channel.Bot.PolicyVersion {
		return mfadomain.ErrUnavailable
	}
	token, err := telegrambot.NewCredentials(credentials.Token.Value())
	if err != nil {
		return mfadomain.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.owner.client.SendCode(ctx, token, channel.TelegramID, code)
}

func botIdentity(snapshot settingsdomain.TelegramBotSnapshot) settingsdomain.TelegramBotIdentity {
	return settingsdomain.TelegramBotIdentity{ID: snapshot.BotID, Username: snapshot.Username}
}

func NewProjectTelegramMFA(manager *ProjectMFA, client ProjectTelegramClient, origin string, deliveryReady func() bool, scope realmscope.Scope, root string) (*ProjectTelegramMFA, error) {
	token, err := secretbox.ForScope(scope, root, "telegram-bot-token:v1")
	if err != nil {
		return nil, err
	}
	webhook, err := secretbox.ForScope(scope, root, "telegram-webhook:v1")
	if err != nil {
		return nil, err
	}
	channel, err := secretbox.ForScope(scope, root, "telegram-channel:v1")
	if err != nil {
		return nil, err
	}
	return &ProjectTelegramMFA{manager: manager, client: client, origin: origin, deliveryReady: deliveryReady, token: token, webhook: webhook, channel: channel}, nil
}

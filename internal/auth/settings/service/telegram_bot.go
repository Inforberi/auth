package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type TelegramBotStored struct {
	domain.TelegramBotSnapshot
	Token       []byte `json:"-"`
	Webhook     []byte `json:"-"`
	StoredBotID int64  `json:"-"`
}

type TelegramBotUpdate struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Identity        domain.TelegramBotIdentity
	Token           []byte `json:"-"`
	Webhook         []byte `json:"-"`
}

type TelegramBotRepository interface {
	ReadTelegramBot(context.Context, accessservice.Principal) (domain.TelegramBotSnapshot, error)
	LoadTelegramBot(context.Context) (TelegramBotStored, error)
	AuthorizeTelegramBotUpdate(context.Context, accessservice.Principal, int64) (TelegramBotStored, error)
	UpdateTelegramBot(context.Context, TelegramBotUpdate) (domain.TelegramBotSnapshot, error)
}

type TelegramBotVerifier interface {
	VerifyTelegramBot(context.Context, domain.TelegramBotToken) (domain.TelegramBotIdentity, error)
}

type TelegramBotTokens interface {
	GenerateToken(...int) (string, error)
}

type TelegramBotLimits struct {
	UserUpdatesPerMinute    int
	ProjectUpdatesPerMinute int
}

type TelegramBotSettings struct {
	repo                       TelegramBotRepository
	tokenCipher, webhookCipher ProviderCipher
	verifier                   TelegramBotVerifier
	limits                     SettingsLimiter
	tokens                     TelegramBotTokens
	config                     TelegramBotLimits
}

func NewTelegramBotSettings(repo TelegramBotRepository, tokenCipher, webhookCipher ProviderCipher, verifier TelegramBotVerifier, limits SettingsLimiter, tokens TelegramBotTokens, config TelegramBotLimits) (*TelegramBotSettings, error) {
	if repo == nil || tokenCipher == nil || webhookCipher == nil || verifier == nil || limits == nil || tokens == nil ||
		config.UserUpdatesPerMinute < 1 || config.ProjectUpdatesPerMinute < 1 {
		return nil, domain.ErrInvalidTelegramBot
	}
	return &TelegramBotSettings{
		repo: repo, tokenCipher: tokenCipher, webhookCipher: webhookCipher,
		verifier: verifier, limits: limits, tokens: tokens, config: config,
	}, nil
}

func (s *TelegramBotSettings) Read(ctx context.Context, actor accessservice.Principal) (domain.TelegramBotSnapshot, error) {
	if actor.Validate() != nil {
		return domain.TelegramBotSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadTelegramBot(ctx, actor)
}

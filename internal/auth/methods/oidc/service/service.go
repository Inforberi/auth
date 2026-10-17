package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type flowRepository interface {
	Save(context.Context, string, string, domain.Flow) error
	Consume(context.Context, string, string) (*domain.Flow, error)
	Allow(context.Context, string, int, int) (bool, error)
}

type Provider interface {
	AuthorizationURL(state string, flow domain.Flow) string
	Verify(context.Context, string, domain.Flow) (accountdomain.IdentityKey, error)
}

type identities interface {
	Resolve(context.Context, accountdomain.IdentityKey, bool) (*accountdomain.User, error)
}

type sessions interface {
	BeginLogin(context.Context, mfaservice.PrimaryProof, string, string) (*sessionservice.CreatedSession, error)
}

type tokens interface {
	GenerateToken(...int) (string, error)
	Hash(string) string
}

type identityManagement interface {
	RequireFresh(context.Context, accountdomain.UserID, string) error
	Link(context.Context, accountdomain.UserID, string, accountdomain.IdentityKey) error
	Unlink(context.Context, accountdomain.UserID, string, string) error
}

type Service struct {
	cfg            Config
	flows          flowRepository
	provider       Provider
	providerSource func(context.Context) (Provider, int64, error)
	identities     identities
	sessions       sessions
	tokens         tokens
	management     identityManagement
}

func New(cfg Config, flows flowRepository, provider Provider, identities identities, sessions sessions, tokens tokens, management identityManagement) *Service {
	return &Service{cfg: cfg, flows: flows, provider: provider, identities: identities, sessions: sessions, tokens: tokens, management: management}
}

func (s *Service) WithProviderSource(source func(context.Context) (Provider, int64, error)) *Service {
	s.providerSource = source
	return s
}

func (s *Service) currentProvider(ctx context.Context) (Provider, int64, error) {
	if s.providerSource != nil {
		return s.providerSource(ctx)
	}
	return s.provider, 0, nil
}

func (s *Service) admit(ctx context.Context, ip string) error {
	if !s.cfg.Enabled {
		return domain.ErrDisabled
	}
	allowed, err := s.flows.Allow(ctx, ip, s.cfg.IPLimit, s.cfg.GlobalLimit)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrLimited
	}
	if s.cfg.CheckPolicy != nil {
		return s.cfg.CheckPolicy(ctx)
	}
	return nil
}

func flowContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}

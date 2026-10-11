package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type flowRepository interface {
	Save(context.Context, string, string, domain.Flow) error
	Consume(context.Context, string, string) (*domain.Flow, error)
	Allow(context.Context, string, int, int) (bool, error)
}

type provider interface {
	AuthorizationURL(state string, flow domain.Flow) string
	Verify(context.Context, string, domain.Flow) (accountdomain.IdentityKey, error)
}

type identities interface {
	Resolve(context.Context, accountdomain.IdentityKey, bool) (*accountdomain.User, error)
}

type sessions interface {
	CreateSessionAtVersion(context.Context, accountdomain.UserID, string, string, int64) (*sessionservice.CreatedSession, error)
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
	cfg        Config
	flows      flowRepository
	provider   provider
	identities identities
	sessions   sessions
	tokens     tokens
	management identityManagement
}

func New(cfg Config, flows flowRepository, provider provider, identities identities, sessions sessions, tokens tokens, management identityManagement) *Service {
	return &Service{cfg: cfg, flows: flows, provider: provider, identities: identities, sessions: sessions, tokens: tokens, management: management}
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
	return nil
}

func flowContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Second)
}

package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type repository interface {
	Issue(context.Context, string, domain.Challenge) error
	Consume(context.Context, string, string) (*AuthenticatedAccount, error)
	IssueReauthentication(context.Context, mfaservice.Proof, string, domain.Challenge) error
	ConfirmReauthentication(context.Context, mfaservice.Proof, string, string, string) (*ReauthenticatedSession, error)
}

type cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}

type limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type sessions interface {
	BeginLogin(context.Context, mfaservice.PrimaryProof, string, string) (*sessionservice.CreatedSession, error)
}

type tokens interface {
	GenerateToken(...int) (string, error)
	Hash(string) string
}

type Service struct {
	repo     repository
	cipher   cipher
	limits   limiter
	sessions sessions
	tokens   tokens
	cfg      Config
}

func New(repo repository, cipher cipher, limits limiter, sessions sessions, tokens tokens, cfg Config) *Service {
	return &Service{repo: repo, cipher: cipher, limits: limits, sessions: sessions, tokens: tokens, cfg: cfg}
}

func (s *Service) limit(ctx context.Context, key string, count int, window time.Duration) error {
	allowed, err := s.limits.Allow(ctx, s.cipher.Digest(key), count, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrLimited
	}
	return nil
}

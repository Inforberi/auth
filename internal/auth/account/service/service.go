package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Repository interface {
	Issue(context.Context, string, domain.Verification, time.Duration) error
	Confirm(context.Context, string) error
	RequireVerified(context.Context, domain.UserID) error
	ClaimDelivery(context.Context) (*domain.VerificationDelivery, error)
	FinishDelivery(context.Context, domain.VerificationDelivery, bool) error
}

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type Cipher interface {
	Seal([]byte) ([]byte, error)
	Open([]byte) ([]byte, error)
	Digest(string) string
}

type Mailer interface {
	SendContext(context.Context, string, string, string) error
}

type Service struct {
	repo    Repository
	limiter Limiter
	cipher  Cipher
	mail    Mailer
	cfg     Config
}

func New(repo Repository, limiter Limiter, cipher Cipher, mail Mailer, cfg Config) *Service {
	return &Service{repo: repo, limiter: limiter, cipher: cipher, mail: mail, cfg: cfg}
}

func (s *Service) RequireVerified(ctx context.Context, id domain.UserID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.RequireVerified(ctx, id)
}

func (s *Service) limit(ctx context.Context, key string, maxRequests int, window time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	allowed, err := s.limiter.Allow(ctx, s.cipher.Digest(key), maxRequests, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrVerificationLimited
	}
	return nil
}

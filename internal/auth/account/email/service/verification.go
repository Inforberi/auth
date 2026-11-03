package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

type Repository interface {
	Issue(context.Context, string, domain.Verification, time.Duration) error
	Confirm(context.Context, string) error
	RequireVerified(context.Context, domain.UserID) error
	ClaimDelivery(context.Context) (*domain.VerificationDelivery, error)
	FinishDelivery(context.Context, domain.VerificationDelivery, bool) error
}

type Verification struct {
	repo    Repository
	limiter accountservice.Limiter
	cipher  accountservice.Cipher
	mail    accountservice.Mailer
	cfg     accountservice.Config
}

func NewVerification(repo Repository, limiter accountservice.Limiter, cipher accountservice.Cipher, mail accountservice.Mailer, cfg accountservice.Config) *Verification {
	if cfg.RegistrationIPLimit == 0 {
		cfg.RegistrationIPLimit = 5
	}
	if cfg.RegistrationGlobalLimit == 0 {
		cfg.RegistrationGlobalLimit = 100
	}
	return &Verification{repo: repo, limiter: limiter, cipher: cipher, mail: mail, cfg: cfg}
}

func (s *Verification) RequireVerified(ctx context.Context, id domain.UserID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.RequireVerified(ctx, id)
}

func (s *Verification) limit(ctx context.Context, key string, maxRequests int, window time.Duration) error {
	return accountservice.Admit(ctx, s.limiter, s.cipher, key, maxRequests, window)
}

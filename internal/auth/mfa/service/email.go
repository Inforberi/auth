package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type EmailFactorRepository interface {
	ReadEmailFactor(context.Context, Proof) (*domain.EmailFactor, error)
	EnableEmailFactor(context.Context, Proof) error
	DisableEmailFactor(context.Context, Proof) error
}

type EmailFactors struct {
	repo   EmailFactorRepository
	cipher Cipher
	limit  Limiter
}

func NewEmailFactors(repo EmailFactorRepository, cipher Cipher, limit Limiter) (*EmailFactors, error) {
	if repo == nil || cipher == nil || limit == nil {
		return nil, domain.ErrUnavailable
	}
	return &EmailFactors{repo: repo, cipher: cipher, limit: limit}, nil
}

func (s *EmailFactors) Status(ctx context.Context, proof Proof) (*domain.EmailFactor, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadEmailFactor(ctx, proof)
}

func (s *EmailFactors) Enable(ctx context.Context, proof Proof) error {
	return s.change(ctx, proof, s.repo.EnableEmailFactor)
}

func (s *EmailFactors) Disable(ctx context.Context, proof Proof) error {
	return s.change(ctx, proof, s.repo.DisableEmailFactor)
}

func (s *EmailFactors) change(ctx context.Context, proof Proof, write func(context.Context, Proof) error) error {
	if err := proof.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := admitBudgets(ctx, s.limit, []Budget{
		{s.cipher.Digest("email-factor:user:" + string(proof.UserID)), 5},
		{s.cipher.Digest("email-factor:project"), 500},
	}); err != nil {
		return err
	}
	return write(ctx, proof)
}

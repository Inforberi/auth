package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type TelegramFactorRepository interface {
	ReadTelegramFactor(context.Context, Proof) (*domain.TelegramFactor, error)
	EnableTelegramFactor(context.Context, Proof, domain.TelegramBotBinding) error
	DisableTelegramFactor(context.Context, Proof) error
}

type TelegramFactorConfig struct {
	Bot                                               domain.TelegramBotBinding
	UserMutationsPerMinute, ProjectMutationsPerMinute int
}

type TelegramFactors struct {
	repo   TelegramFactorRepository
	cipher Cipher
	limits Limiter
	cfg    TelegramFactorConfig
}

func NewTelegramFactors(repo TelegramFactorRepository, cipher Cipher, limits Limiter, cfg TelegramFactorConfig) (*TelegramFactors, error) {
	if repo == nil || cipher == nil || limits == nil || !cfg.Bot.Valid() ||
		cfg.UserMutationsPerMinute < 1 || cfg.ProjectMutationsPerMinute < 1 {
		return nil, domain.ErrUnavailable
	}
	return &TelegramFactors{repo: repo, cipher: cipher, limits: limits, cfg: cfg}, nil
}

func (s *TelegramFactors) Status(ctx context.Context, proof Proof) (*domain.TelegramFactor, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadTelegramFactor(ctx, proof)
}

func (s *TelegramFactors) Enable(ctx context.Context, proof Proof) error {
	return s.change(ctx, proof, func(ctx context.Context, proof Proof) error {
		return s.repo.EnableTelegramFactor(ctx, proof, s.cfg.Bot)
	})
}

func (s *TelegramFactors) Disable(ctx context.Context, proof Proof) error {
	return s.change(ctx, proof, s.repo.DisableTelegramFactor)
}

func (s *TelegramFactors) change(ctx context.Context, proof Proof, write func(context.Context, Proof) error) error {
	if err := proof.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := admitBudgets(ctx, s.limits, []Budget{
		{s.cipher.Digest("telegram-factor:user:" + string(proof.UserID)), s.cfg.UserMutationsPerMinute},
		{s.cipher.Digest("telegram-factor:project"), s.cfg.ProjectMutationsPerMinute},
	}); err != nil {
		return err
	}
	return write(ctx, proof)
}

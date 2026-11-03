package service

import (
	"context"
	"time"

	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type TelegramFactorRepository interface {
	ReadTelegramFactor(context.Context, mfaservice.Proof) (*domain.TelegramFactor, error)
	EnableTelegramFactor(context.Context, FactorMutation, domain.TelegramBotBinding) error
	DisableTelegramFactor(context.Context, FactorMutation) error
}

type TelegramFactorConfig struct {
	Bot                                               domain.TelegramBotBinding
	UserMutationsPerMinute, ProjectMutationsPerMinute int
}

type TelegramFactors struct {
	repo   TelegramFactorRepository
	cipher mfaservice.Cipher
	limits mfaservice.Limiter
	cfg    TelegramFactorConfig
}

func NewTelegramFactors(repo TelegramFactorRepository, cipher mfaservice.Cipher, limits mfaservice.Limiter, cfg TelegramFactorConfig) (*TelegramFactors, error) {
	if repo == nil || cipher == nil || limits == nil || !cfg.Bot.Valid() ||
		cfg.UserMutationsPerMinute < 1 || cfg.ProjectMutationsPerMinute < 1 {
		return nil, domain.ErrUnavailable
	}
	return &TelegramFactors{repo: repo, cipher: cipher, limits: limits, cfg: cfg}, nil
}

func (s *TelegramFactors) Status(ctx context.Context, proof mfaservice.Proof) (*domain.TelegramFactor, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadTelegramFactor(ctx, proof)
}

func (s *TelegramFactors) Enable(ctx context.Context, proof mfaservice.Proof) error {
	return s.change(ctx, proof, func(ctx context.Context, input FactorMutation) error {
		return s.repo.EnableTelegramFactor(ctx, input, s.cfg.Bot)
	})
}

func (s *TelegramFactors) Disable(ctx context.Context, proof mfaservice.Proof) error {
	return s.change(ctx, proof, s.repo.DisableTelegramFactor)
}

func (s *TelegramFactors) change(ctx context.Context, proof mfaservice.Proof, write func(context.Context, FactorMutation) error) error {
	if err := proof.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := mfaservice.AdmitBudgets(ctx, s.limits, []mfaservice.Budget{
		{Key: s.cipher.Digest("telegram-factor:user:" + string(proof.UserID)), Count: s.cfg.UserMutationsPerMinute},
		{Key: s.cipher.Digest("telegram-factor:project"), Count: s.cfg.ProjectMutationsPerMinute},
	}); err != nil {
		return err
	}
	return write(ctx, FactorMutation{Proof: proof, PrepareNotice: func(email, event string, at time.Time) ([]byte, error) {
		payload, err := mfadelivery.SealNotice(s.cipher, email, event, "", at)
		if err != nil {
			return nil, domain.ErrUnavailable
		}
		return payload, nil
	}})
}

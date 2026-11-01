package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type MethodSelection interface {
	SelectMFAMethod(context.Context, PrimaryProof) (domain.Method, error)
}

type FactorStarter interface {
	Start(context.Context, PrimaryProof, string) (*LoginChallenge, error)
	StartNative(context.Context, PrimaryProof, NativeTarget, string) (*LoginChallenge, error)
}

// Completion remains bound to the method and target recorded in SQL.
type Selector struct {
	*Login
	repo            MethodSelection
	email, telegram FactorStarter
}

func NewSelector(login *Login, repo MethodSelection, email, telegram FactorStarter) *Selector {
	return &Selector{Login: login, repo: repo, email: email, telegram: telegram}
}

func (s *Selector) starter(ctx context.Context, proof PrimaryProof) (FactorStarter, error) {
	if !ValidPrimary(proof) {
		return nil, domain.ErrProofRequired
	}
	method, err := s.repo.SelectMFAMethod(ctx, proof)
	if err != nil {
		return nil, err
	}
	switch method {
	case domain.TOTP:
		return s.Login, nil
	case domain.EmailCode:
		if s.email != nil {
			return s.email, nil
		}
	case domain.TelegramCode:
		if s.telegram != nil {
			return s.telegram, nil
		}
	}
	return nil, domain.ErrUnavailable
}

func (s *Selector) Start(ctx context.Context, proof PrimaryProof, ip string) (*LoginChallenge, error) {
	starter, err := s.starter(ctx, proof)
	if err != nil {
		return nil, err
	}
	return starter.Start(ctx, proof, ip)
}

func (s *Selector) StartNative(ctx context.Context, proof PrimaryProof, target NativeTarget, ip string) (*LoginChallenge, error) {
	starter, err := s.starter(ctx, proof)
	if err != nil {
		return nil, err
	}
	return starter.StartNative(ctx, proof, target, ip)
}

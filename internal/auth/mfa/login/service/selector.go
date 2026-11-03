package service

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type MethodSelection interface {
	ReadMethodSelection(context.Context, mfaservice.PrimaryProof) (domain.MethodSelection, error)
}

type FactorStarter interface {
	Start(context.Context, mfaservice.PrimaryProof, string) (*LoginChallenge, error)
	StartNative(context.Context, mfaservice.PrimaryProof, mfaservice.NativeTarget, string) (*LoginChallenge, error)
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

func (s *Selector) starter(ctx context.Context, proof mfaservice.PrimaryProof) (FactorStarter, error) {
	if !mfaservice.ValidPrimary(proof) {
		return nil, domain.ErrProofRequired
	}
	state, err := s.repo.ReadMethodSelection(ctx, proof)
	if err != nil {
		return nil, err
	}
	method, err := state.Select(proof.Method, proof.Administrative)
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

func (s *Selector) Start(ctx context.Context, proof mfaservice.PrimaryProof, ip string) (*LoginChallenge, error) {
	starter, err := s.starter(ctx, proof)
	if err != nil {
		return nil, err
	}
	return starter.Start(ctx, proof, ip)
}

func (s *Selector) StartNative(ctx context.Context, proof mfaservice.PrimaryProof, target mfaservice.NativeTarget, ip string) (*LoginChallenge, error) {
	starter, err := s.starter(ctx, proof)
	if err != nil {
		return nil, err
	}
	return starter.StartNative(ctx, proof, target, ip)
}

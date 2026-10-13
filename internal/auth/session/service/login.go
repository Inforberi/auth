package service

import (
	"context"
	"errors"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type mfaLogin interface {
	Start(context.Context, mfaservice.PrimaryProof, string) (*mfaservice.LoginChallenge, error)
}

type Login struct {
	*SessionService
	mfa mfaLogin
}

func NewLogin(sessions *SessionService, mfa mfaLogin) *Login {
	return &Login{SessionService: sessions, mfa: mfa}
}

func (s *SessionService) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*CreatedSession, error) {
	return s.CreateSessionAtVersion(ctx, proof.UserID, agent, ip, proof.AuthVersion)
}

func (s *Login) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*CreatedSession, error) {
	result, err := s.CreateSessionAtVersion(ctx, proof.UserID, agent, ip, proof.AuthVersion)
	if !errors.Is(err, domain.ErrMFARequired) || s.mfa == nil {
		return result, err
	}
	challenge, err := s.mfa.Start(ctx, proof, ip)
	if err != nil {
		return nil, err
	}
	return &CreatedSession{Challenge: challenge, ExpiresAt: challenge.ExpiresAt}, nil
}

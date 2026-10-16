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
	if proof.Administrative {
		return nil, domain.ErrMFARequired
	}
	return s.createSession(ctx, proof.UserID, agent, ip, proof.AuthVersion, &proof)
}

func (s *Login) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*CreatedSession, error) {
	if !proof.Administrative {
		result, err := s.createSession(ctx, proof.UserID, agent, ip, proof.AuthVersion, &proof)
		if !errors.Is(err, domain.ErrMFARequired) || s.mfa == nil {
			return result, err
		}
	}
	if s.mfa == nil {
		return nil, domain.ErrMFARequired
	}
	challenge, err := s.mfa.Start(ctx, proof, ip)
	if err != nil {
		return nil, err
	}
	return &CreatedSession{Challenge: challenge, ExpiresAt: challenge.ExpiresAt}, nil
}

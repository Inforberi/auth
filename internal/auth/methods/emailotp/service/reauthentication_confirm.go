package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type ReauthenticationInput struct {
	Proof             mfaservice.Proof
	Code, Binding, IP string
}

type ReauthenticatedSession struct {
	Token                 string `json:"-"`
	VerifiedAt, ExpiresAt time.Time
}

func (s *Service) ConfirmReauthentication(ctx context.Context, input ReauthenticationInput) (*ReauthenticatedSession, error) {
	if !s.cfg.ReauthenticationEnabled {
		return nil, domain.ErrDisabled
	}
	if err := input.Proof.Validate(); err != nil {
		return nil, err
	}
	if !domain.ValidBinding(input.Binding) || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, budget := range []struct {
		key   string
		count int
	}{
		{"confirm:ip:" + input.IP, 10},
		{"confirm:project", s.cfg.ConfirmGlobalLimit},
		{"reauth:confirm:user:" + string(input.Proof.UserID), domain.MaxAttempts},
	} {
		if err := s.limit(ctx, budget.key, budget.count, time.Minute); err != nil {
			return nil, err
		}
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	result, err := s.repo.ConfirmReauthentication(ctx, input.Proof,
		s.cipher.Digest("reauth:binding:"+input.Binding), s.cipher.Digest("reauth:code:"+input.Binding+":"+input.Code), s.tokens.Hash(raw))
	if err != nil {
		return nil, err
	}
	result.Token = raw
	return result, nil
}

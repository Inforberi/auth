package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *Service) RequestReauthentication(ctx context.Context, proof mfaservice.Proof, input, ip string) (*RequestedCode, error) {
	if !s.cfg.ReauthenticationEnabled {
		return nil, domain.ErrDisabled
	}
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	email, err := accountdomain.NewEmail(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.limit(ctx, "reauth:request:user:"+string(proof.UserID), 3, 15*time.Minute); err != nil {
		return nil, err
	}
	if err := s.requestLimits(ctx, email.String(), ip); err != nil {
		return nil, err
	}
	result, challenge, err := s.prepareCode(email.String(), "подтверждения управления MFA", "reauth:")
	if err != nil {
		return nil, err
	}
	if err := s.repo.IssueReauthentication(ctx, proof, email.String(), challenge); err != nil {
		return nil, err
	}
	return result, nil
}

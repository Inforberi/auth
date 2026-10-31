package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type EmailPreparationConfirmation struct {
	Proof             mfaservice.Proof
	Binding, Code, IP string
}

func (s *EmailPreparation) Confirm(ctx context.Context, input EmailPreparationConfirmation) (*ReauthenticatedSession, error) {
	if err := input.Proof.Validate(); err != nil {
		return nil, err
	}
	if !domain.ValidBinding(input.Binding) || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidPreparation
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.Proof, input.IP, true); err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	result, err := s.repo.ConfirmEmailPreparation(ctx, input.Proof, s.cipher.Digest(emailPreparationPurpose+"binding:"+input.Binding), s.cipher.Digest(emailPreparationPurpose+"code:"+input.Binding+":"+input.Code), s.tokens.Hash(raw))
	if err != nil {
		return nil, err
	}
	result.Token = raw
	return result, nil
}

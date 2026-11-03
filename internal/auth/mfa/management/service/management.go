package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *Service) Disable(ctx context.Context, proof mfaservice.Proof) error {
	if !mfaservice.ValidProof(proof) {
		return domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, proof.UserID); err != nil {
		return err
	}
	return s.repo.Disable(ctx, proof, domain.CanDisableTOTP)
}

func (s *Service) RegenerateRecovery(ctx context.Context, proof mfaservice.Proof) (*mfaservice.RecoveryCodes, error) {
	if !mfaservice.ValidProof(proof) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, proof.UserID); err != nil {
		return nil, err
	}
	codes, digests, err := s.recoveryCodes(proof.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RegenerateRecovery(ctx, proof, digests); err != nil {
		return nil, err
	}
	return &mfaservice.RecoveryCodes{Codes: codes}, nil
}

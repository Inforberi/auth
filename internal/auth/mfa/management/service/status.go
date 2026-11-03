package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type SecurityStatus struct {
	TOTPEnabled                  bool
	RequiredByPolicy             bool
	RequiredByRole               bool
	RequiredByAdministration     bool
	RecoveryCodesRemaining       int
	VerifiedEmail                bool
	PasswordConfigured           bool
	EmailReauthenticationEnabled bool
	FreshPrimaryProof            bool
	FreshMFAProof                bool
}

func (s *Service) Status(ctx context.Context, proof mfaservice.Proof) (*SecurityStatus, error) {
	if !mfaservice.ValidProof(proof) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.Status(ctx, proof)
}

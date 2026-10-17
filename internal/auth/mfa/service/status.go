package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type SecurityStatus struct {
	TOTPEnabled                  bool
	RequiredByRole               bool
	RequiredByAdministration     bool
	RecoveryCodesRemaining       int
	VerifiedEmail                bool
	PasswordConfigured           bool
	EmailReauthenticationEnabled bool
	FreshPrimaryProof            bool
	FreshMFAProof                bool
}

func (s *Service) Status(ctx context.Context, proof Proof) (*SecurityStatus, error) {
	if !validProof(proof) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.Status(ctx, proof)
}

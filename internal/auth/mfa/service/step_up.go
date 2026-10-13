package service

import (
	"context"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type StepUpInput struct {
	Proof    Proof
	Code     string
	Recovery bool
}

type StepUpCommit struct {
	VerifiedAt, ExpiresAt time.Time
}

type StepUpResult struct {
	Token                 string `json:"-"`
	VerifiedAt, ExpiresAt time.Time
}

func (s *Service) StepUp(ctx context.Context, input StepUpInput) (*StepUpResult, error) {
	if !validProof(input.Proof) {
		return nil, domain.ErrProofRequired
	}
	if (input.Recovery && !domain.ValidRecoveryCode(input.Code)) || (!input.Recovery && !domain.ValidCode(input.Code)) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.Proof.UserID); err != nil {
		return nil, err
	}
	// A higher operational budget must not increase the online factor-guessing budget.
	allowed, err := s.limit.Allow(ctx, s.cipher.Digest("step-up:"+string(input.Proof.UserID)), 5, time.Minute)
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	if !allowed {
		return nil, domain.ErrLimited
	}
	if s.tokens == nil {
		return nil, domain.ErrUnavailable
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	digest := ""
	if input.Recovery {
		digest = s.cipher.Digest("recovery:" + string(input.Proof.UserID) + ":" + input.Code)
	}
	result, err := s.repo.StepUp(ctx, input.Proof, s.tokens.Hash(raw), s.check(input.Proof.UserID, input.Code), digest)
	if err != nil {
		return nil, err
	}
	return &StepUpResult{Token: raw, VerifiedAt: result.VerifiedAt, ExpiresAt: result.ExpiresAt}, nil
}

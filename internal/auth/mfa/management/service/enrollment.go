package service

import (
	"context"
	"encoding/base64"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *Service) StartEnrollment(ctx context.Context, proof mfaservice.Proof) (*mfaservice.Enrollment, error) {
	return s.startEnrollment(ctx, proof, false)
}

func (s *Service) StartReplacement(ctx context.Context, proof mfaservice.Proof) (*mfaservice.Enrollment, error) {
	return s.startEnrollment(ctx, proof, true)
}

func (s *Service) startEnrollment(ctx context.Context, proof mfaservice.Proof, replace bool) (*mfaservice.Enrollment, error) {
	if !mfaservice.ValidProof(proof) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, proof.UserID); err != nil {
		return nil, err
	}
	enrollment, encrypted, err := mfaservice.PrepareEnrollment(s.code, s.cipher, s.issuer, proof.UserID)
	if err != nil {
		return nil, err
	}
	save := s.repo.SaveEnrollment
	if replace {
		save = s.repo.SaveReplacement
	}
	expires, err := save(ctx, proof, s.cipher.Digest("enrollment:"+enrollment.Token), encrypted)
	if err != nil {
		return nil, err
	}
	enrollment.ExpiresAt = expires
	return enrollment, nil
}

type ConfirmInput struct {
	Proof mfaservice.Proof
	Token string
	Code  string
}

func (s *Service) ConfirmEnrollment(ctx context.Context, input ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	return s.confirmEnrollment(ctx, input, false)
}

func (s *Service) ConfirmReplacement(ctx context.Context, input ConfirmInput) (*mfaservice.RecoveryCodes, error) {
	return s.confirmEnrollment(ctx, input, true)
}

func (s *Service) confirmEnrollment(ctx context.Context, input ConfirmInput, replace bool) (*mfaservice.RecoveryCodes, error) {
	if !mfaservice.ValidProof(input.Proof) {
		return nil, domain.ErrProofRequired
	}
	if len(input.Token) != 43 || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidCode
	}
	raw, err := base64.RawURLEncoding.DecodeString(input.Token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != input.Token {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.Proof.UserID); err != nil {
		return nil, err
	}
	codes, digests, err := s.recoveryCodes(input.Proof.UserID)
	if err != nil {
		return nil, err
	}
	confirm := s.repo.ConfirmEnrollment
	if replace {
		confirm = s.repo.ConfirmReplacement
	}
	if err := confirm(ctx, input.Proof, s.cipher.Digest("enrollment:"+input.Token),
		s.check(input.Proof.UserID, input.Code), digests); err != nil {
		return nil, err
	}
	return &mfaservice.RecoveryCodes{Codes: codes}, nil
}

func (s *Service) recoveryCodes(user accountdomain.UserID) ([]string, []string, error) {
	return mfaservice.GenerateRecoveryCodes(s.cipher, user)
}

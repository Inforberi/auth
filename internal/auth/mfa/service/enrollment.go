package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type Enrollment struct {
	Token     string `json:"-"`
	Secret    string `json:"-"`
	URI       string `json:"-"`
	ExpiresAt time.Time
}

func (s *Service) StartEnrollment(ctx context.Context, proof Proof) (*Enrollment, error) {
	return s.startEnrollment(ctx, proof, false)
}

func (s *Service) StartReplacement(ctx context.Context, proof Proof) (*Enrollment, error) {
	return s.startEnrollment(ctx, proof, true)
}

func (s *Service) startEnrollment(ctx context.Context, proof Proof, replace bool) (*Enrollment, error) {
	if !validProof(proof) {
		return nil, domain.ErrProofRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, proof.UserID); err != nil {
		return nil, err
	}
	secret, uri, err := s.code.Generate(s.issuer, string(proof.UserID))
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	encrypted, err := s.cipher.Seal([]byte(string(proof.UserID) + "\x00" + secret))
	if err != nil {
		return nil, domain.ErrUnavailable
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	save := s.repo.SaveEnrollment
	if replace {
		save = s.repo.SaveReplacement
	}
	expires, err := save(ctx, proof, s.cipher.Digest("enrollment:"+token), encrypted)
	if err != nil {
		return nil, err
	}
	return &Enrollment{Token: token, Secret: secret, URI: uri, ExpiresAt: expires}, nil
}

type ConfirmInput struct {
	Proof Proof
	Token string
	Code  string
}

type RecoveryCodes struct {
	Codes []string `json:"-"`
}

func (s *Service) ConfirmEnrollment(ctx context.Context, input ConfirmInput) (*RecoveryCodes, error) {
	return s.confirmEnrollment(ctx, input, false)
}

func (s *Service) ConfirmReplacement(ctx context.Context, input ConfirmInput) (*RecoveryCodes, error) {
	return s.confirmEnrollment(ctx, input, true)
}

func (s *Service) confirmEnrollment(ctx context.Context, input ConfirmInput, replace bool) (*RecoveryCodes, error) {
	if !validProof(input.Proof) {
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
	return &RecoveryCodes{Codes: codes}, nil
}

func (s *Service) recoveryCodes(user accountdomain.UserID) ([]string, []string, error) {
	codes, digests := make([]string, domain.RecoveryCodeCount), make([]string, domain.RecoveryCodeCount)
	for index := range codes {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, nil, err
		}
		codes[index] = hex.EncodeToString(entropy[:])
		digests[index] = s.cipher.Digest("recovery:" + string(user) + ":" + codes[index])
	}
	return codes, digests, nil
}

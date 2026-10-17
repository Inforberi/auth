package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type LoginEnrollmentInput struct {
	Challenge, Binding, IP string
}

type ConfirmLoginEnrollmentInput struct {
	LoginEnrollmentInput
	Token, Code string
}

type LoginEnrollmentParams struct {
	AllowPrimary                                   func(string, string) bool
	ChallengeDigest, BindingHash, EnrollmentDigest string
	Secret                                         []byte
}

func (s *Login) StartRequiredEnrollment(ctx context.Context, input LoginEnrollmentInput) (*Enrollment, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	user, params, err := s.admitEnrollment(ctx, input)
	if err != nil {
		return nil, err
	}
	enrollment, encrypted, err := prepareEnrollment(s.code, s.cipher, s.cfg.Issuer, user)
	if err != nil {
		return nil, err
	}
	params.EnrollmentDigest, params.Secret = s.cipher.Digest("enrollment:"+enrollment.Token), encrypted
	expires, err := s.repo.SaveLoginEnrollment(ctx, params)
	if err != nil {
		return nil, err
	}
	enrollment.ExpiresAt = expires
	return enrollment, nil
}

func (s *Login) ConfirmRequiredEnrollment(ctx context.Context, input ConfirmLoginEnrollmentInput) (*RecoveryCodes, error) {
	if !validLoginToken(input.Token) || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	user, params, err := s.admitEnrollment(ctx, input.LoginEnrollmentInput)
	if err != nil {
		return nil, err
	}
	if err := admitFactorUser(ctx, s.cipher, s.limit, s.cfg.UserLimitPerMinute, user); err != nil {
		return nil, err
	}
	params.EnrollmentDigest = s.cipher.Digest("enrollment:" + input.Token)
	codes, digests, err := generateRecoveryCodes(s.cipher, user)
	if err != nil {
		return nil, err
	}
	if err := s.repo.ConfirmLoginEnrollment(ctx, params, factorCheck(s.cipher, s.code, user, input.Code), digests); err != nil {
		return nil, err
	}
	return &RecoveryCodes{Codes: codes}, nil
}

func (s *Login) admitEnrollment(ctx context.Context, input LoginEnrollmentInput) (accountdomain.UserID, LoginEnrollmentParams, error) {
	var params LoginEnrollmentParams
	if !validLoginToken(input.Challenge) || !validLoginToken(input.Binding) || len(input.IP) > 64 {
		return "", params, domain.ErrInvalidCode
	}
	if err := s.admitLogin(ctx, "enrollment", input.Challenge+":"+input.Binding, input.IP, 5); err != nil {
		return "", params, err
	}
	params.ChallengeDigest, params.BindingHash = s.cipher.Digest("login:"+input.Challenge), s.cipher.Digest("browser:"+input.Binding)
	params.AllowPrimary = s.cfg.AllowPrimary
	user, err := s.repo.FindLoginOwner(ctx, params.ChallengeDigest, params.BindingHash)
	if err != nil {
		return "", params, err
	}
	return user, params, nil
}

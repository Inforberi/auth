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
	Native                                         bool
	AllowPrimary                                   func(string, string) bool
	ChallengeDigest, BindingHash, EnrollmentDigest string
	Secret                                         []byte
}

func (s *Login) StartRequiredEnrollment(ctx context.Context, input LoginEnrollmentInput) (*Enrollment, error) {
	return s.startRequiredEnrollment(ctx, input, false)
}

func (s *Login) StartNativeRequiredEnrollment(ctx context.Context, input LoginEnrollmentInput) (*Enrollment, error) {
	return s.startRequiredEnrollment(ctx, input, true)
}

func (s *Login) startRequiredEnrollment(ctx context.Context, input LoginEnrollmentInput, native bool) (*Enrollment, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	user, params, err := s.admitEnrollmentFor(ctx, input, native)
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
	return s.confirmRequiredEnrollment(ctx, input, false)
}

func (s *Login) ConfirmNativeRequiredEnrollment(ctx context.Context, input ConfirmLoginEnrollmentInput) (*RecoveryCodes, error) {
	return s.confirmRequiredEnrollment(ctx, input, true)
}

func (s *Login) confirmRequiredEnrollment(ctx context.Context, input ConfirmLoginEnrollmentInput, native bool) (*RecoveryCodes, error) {
	if !validLoginToken(input.Token) || !domain.ValidCode(input.Code) {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	user, params, err := s.admitEnrollmentFor(ctx, input.LoginEnrollmentInput, native)
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

func (s *Login) admitEnrollmentFor(ctx context.Context, input LoginEnrollmentInput, native bool) (accountdomain.UserID, LoginEnrollmentParams, error) {
	var params LoginEnrollmentParams
	params.Native = native
	if !validLoginToken(input.Challenge) || !validLoginToken(input.Binding) || len(input.IP) > 64 {
		return "", params, domain.ErrInvalidCode
	}
	if err := s.admitLogin(ctx, "enrollment", input.Challenge+":"+input.Binding, input.IP, 5); err != nil {
		return "", params, err
	}
	params.ChallengeDigest, params.BindingHash = s.cipher.Digest("login:"+input.Challenge), s.cipher.Digest("browser:"+input.Binding)
	if native {
		params.ChallengeDigest, params.BindingHash = s.cipher.Digest("native-login:"+input.Challenge), s.cipher.Digest("native-binding:"+input.Binding)
	}
	params.AllowPrimary = s.cfg.AllowPrimary
	find := s.repo.FindLoginOwner
	if native {
		find = s.repo.FindNativeLoginOwner
	}
	user, err := find(ctx, params.ChallengeDigest, params.BindingHash)
	if err != nil {
		return "", params, err
	}
	return user, params, nil
}

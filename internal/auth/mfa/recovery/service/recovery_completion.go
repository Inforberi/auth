package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfadelivery "github.com/Inforberi/financial-intelligence/internal/auth/mfa/delivery/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type CompleteRecoveryInput struct {
	RequestID, Token, Binding, Code, IP string
}

type RecoveryCompletion struct {
	UserID                         accountdomain.UserID
	RequestID, Digest, BindingHash string
	RecoveryDigests                []string
	Check                          mfaservice.Check
	AllowPrimary                   func(method, issuer string) bool
	PrepareNotice                  func(email string, at time.Time) ([]byte, error)
}

func (s *Recovery) Complete(ctx context.Context, input CompleteRecoveryInput) (*mfaservice.RecoveryCodes, error) {
	if !s.enabled {
		return nil, domain.ErrUnavailable
	}
	if !accountdomain.ValidUserID(accountdomain.UserID(input.RequestID)) || !mfaservice.ValidToken(input.Token) ||
		!mfaservice.ValidToken(input.Binding) || !domain.ValidCode(input.Code) || len(input.IP) > 64 {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := mfaservice.AdmitLogin(ctx, s.cipher, s.limit, s.cfg, "recovery-complete", input.Token+":"+input.Binding, input.IP, 5); err != nil {
		return nil, err
	}
	digest, binding := s.cipher.Digest("login:"+input.Token), s.cipher.Digest("browser:"+input.Binding)
	user, err := s.repo.FindRecoveryOwner(ctx, input.RequestID, digest, binding)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.AdmitFactorUser(ctx, s.cipher, s.limit, user); err != nil {
		return nil, err
	}
	codes, digests, err := mfaservice.GenerateRecoveryCodes(s.cipher, user)
	if err != nil {
		return nil, err
	}
	err = s.repo.CompleteRecovery(ctx, RecoveryCompletion{
		UserID: user, RequestID: input.RequestID, Digest: digest, BindingHash: binding, RecoveryDigests: digests,
		Check: mfaservice.FactorCheck(s.cipher, s.code, user, input.Code), AllowPrimary: s.cfg.AllowPrimary,
		PrepareNotice: func(email string, at time.Time) ([]byte, error) {
			return mfadelivery.SealRecoveryNotice(s.cipher, email, input.RequestID, at)
		},
	})
	if err != nil {
		return nil, err
	}
	return &mfaservice.RecoveryCodes{Codes: codes}, nil
}

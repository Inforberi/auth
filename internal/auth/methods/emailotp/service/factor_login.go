package service

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

const emailLoginPurpose = "mfa-email-login:"

type EmailLoginChannel struct {
	ID    accountdomain.AddressID
	Email string
}

type EmailLoginIntent struct {
	Proof               mfaservice.PrimaryProof
	Target              *mfaservice.NativeTarget
	Channel             EmailLoginChannel
	Digest, BindingHash string
	Code                domain.Challenge
}

type emailLoginRepository interface {
	EmailLoginChannel(context.Context, mfaservice.PrimaryProof) (EmailLoginChannel, error)
	SaveEmailLoginChallenge(context.Context, EmailLoginIntent, time.Duration) (*mfalogin.LoginChallengeState, error)
	FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
	FindNativeLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
	CompleteLogin(context.Context, mfalogin.LoginCompletion, mfalogin.LoginFactor) (*mfalogin.LoginCommit, error)
}

type EmailLogin struct {
	repo   emailLoginRepository
	mail   cipher
	mfa    mfaservice.Cipher
	limits mfaservice.Limiter
	tokens tokens
	cfg    mfaservice.LoginConfig
}

func NewEmailLogin(repo emailLoginRepository, mail cipher, mfa mfaservice.Cipher, limits mfaservice.Limiter, tokens tokens, cfg mfaservice.LoginConfig) (*EmailLogin, error) {
	if repo == nil || mail == nil || mfa == nil || limits == nil || tokens == nil || cfg.Validate() != nil {
		return nil, errors.New("invalid email MFA login configuration")
	}
	return &EmailLogin{repo: repo, mail: mail, mfa: mfa, limits: limits, tokens: tokens, cfg: cfg}, nil
}

func (s *EmailLogin) admit(ctx context.Context, phase, subject, ip string, count int) error {
	key := s.mfa.Digest(emailLoginPurpose + phase + ":" + subject)
	if phase == "start" {
		key = s.mfa.Digest("user:" + subject)
	}
	allowed, err := s.limits.AllowAll(ctx, []mfaservice.Budget{
		{Key: key, Count: count},
		{Key: "login:ip:" + s.mfa.Digest(ip), Count: s.cfg.IPLimitPerMinute},
		{Key: "project", Count: s.cfg.GlobalLimitPerMinute},
	})
	if err != nil {
		return mfadomain.ErrUnavailable
	}
	if !allowed {
		return mfadomain.ErrLimited
	}
	return nil
}

func (s *EmailLogin) identifiers(token, binding string, native bool) (string, string) {
	profile := "browser:"
	if native {
		profile = "api:"
	}
	return s.mfa.Digest(emailLoginPurpose + profile + token), s.mfa.Digest(emailLoginPurpose + profile + "binding:" + binding)
}

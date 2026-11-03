package service

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type LoginRepository interface {
	FindLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
	SaveLoginChallenge(context.Context, mfaservice.PrimaryProof, string, string, time.Duration) (*LoginChallengeState, error)
	CompleteLogin(context.Context, LoginCompletion, LoginFactor) (*LoginCommit, error)
	SaveLoginEnrollment(context.Context, LoginEnrollmentParams) (time.Time, error)
	ConfirmLoginEnrollment(context.Context, LoginEnrollmentParams, mfaservice.Check, []string) error
	SaveNativeLoginChallenge(context.Context, mfaservice.PrimaryProof, mfaservice.NativeTarget, string, string, time.Duration) (*LoginChallengeState, error)
	FindNativeLoginOwner(context.Context, string, string) (accountdomain.UserID, error)
}

type LoginFactor func(accountdomain.UserID) (mfaservice.Check, string)

type Login struct {
	repo   LoginRepository
	cipher mfaservice.Cipher
	code   mfaservice.Authenticator
	limit  mfaservice.Limiter
	tokens mfaservice.Tokens
	cfg    mfaservice.LoginConfig
}

func NewLogin(repo LoginRepository, cipher mfaservice.Cipher, code mfaservice.Authenticator, limit mfaservice.Limiter, tokens mfaservice.Tokens, cfg mfaservice.LoginConfig) (*Login, error) {
	if repo == nil || cipher == nil || code == nil || limit == nil || tokens == nil || cfg.Validate() != nil {
		return nil, errors.New("invalid MFA login configuration")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "Auth"
	}
	return &Login{repo: repo, cipher: cipher, code: code, limit: limit, tokens: tokens, cfg: cfg}, nil
}

type LoginChallengeState struct {
	Method             domain.Method
	RecoveryRequired   bool
	ExpiresAt          time.Time
	EnrollmentRequired bool
}

type LoginChallenge struct {
	Method             domain.Method
	RecoveryRequired   bool
	Token              string `json:"-"`
	Binding            string `json:"-"`
	ExpiresAt          time.Time
	EnrollmentRequired bool
}

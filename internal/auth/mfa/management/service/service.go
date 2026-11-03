package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type Repository interface {
	Status(context.Context, mfaservice.Proof) (*SecurityStatus, error)
	SaveEnrollment(context.Context, mfaservice.Proof, string, []byte) (time.Time, error)
	ConfirmEnrollment(context.Context, mfaservice.Proof, string, mfaservice.Check, []string) error
	Consume(context.Context, accountdomain.UserID, int64, mfaservice.Check, string) (time.Time, error)
	SaveReplacement(context.Context, mfaservice.Proof, string, []byte) (time.Time, error)
	ConfirmReplacement(context.Context, mfaservice.Proof, string, mfaservice.Check, []string) error
	StepUp(context.Context, mfaservice.Proof, string, mfaservice.Check, string) (*StepUpCommit, error)
	Disable(context.Context, mfaservice.Proof, func(domain.DisableState) error) error
	RegenerateRecovery(context.Context, mfaservice.Proof, []string) error
}

type Service struct {
	repo                   Repository
	cipher                 mfaservice.Cipher
	code                   mfaservice.Authenticator
	limit                  mfaservice.Limiter
	issuer                 string
	tokens                 mfaservice.Tokens
	userLimit, globalLimit int
}

func New(repo Repository, cipher mfaservice.Cipher, code mfaservice.Authenticator, limit mfaservice.Limiter, issuer string) *Service {
	return &Service{repo: repo, cipher: cipher, code: code, limit: limit, issuer: issuer, userLimit: 5, globalLimit: 500}
}

func NewConfigured(repo Repository, cipher mfaservice.Cipher, code mfaservice.Authenticator, limit mfaservice.Limiter, tokens mfaservice.Tokens, cfg mfaservice.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled || repo == nil || cipher == nil || code == nil || limit == nil || tokens == nil {
		return nil, domain.ErrUnavailable
	}
	s := New(repo, cipher, code, limit, cfg.Issuer)
	s.tokens, s.userLimit, s.globalLimit = tokens, cfg.UserLimitPerMinute, cfg.GlobalLimitPerMinute
	return s, nil
}

func (s *Service) admit(ctx context.Context, user accountdomain.UserID) error {
	if s.limit == nil {
		return domain.ErrUnavailable
	}
	return mfaservice.AdmitBudgets(ctx, s.limit, []mfaservice.Budget{
		{Key: s.cipher.Digest("user:" + string(user)), Count: s.userLimit}, {Key: "project", Count: s.globalLimit},
	})
}

package service

import (
	"context"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type TemporaryProvisionInput struct {
	Actor          accessservice.Principal
	IdempotencyKey string
	Email          string
}

type TemporaryReissueInput struct {
	Actor          accessservice.Principal
	UserID         accountdomain.UserID
	IdempotencyKey string
}

type TemporaryIssueResult struct {
	UserID    accountdomain.UserID
	Reused    bool
	ExpiresAt time.Time
	Password  string `json:"-"`
}

func (s *TemporaryPasswordService) Provision(ctx context.Context, input TemporaryProvisionInput) (*TemporaryIssueResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrTemporaryPasswordDisabled
	}
	if input.Actor.Validate() != nil || !accountdomain.ValidUserID(accountdomain.UserID(input.IdempotencyKey)) {
		return nil, accountdomain.ErrProvisionConflict
	}
	email, err := accountdomain.NewEmail(input.Email)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.limitIssue(ctx, input.Actor.UserID); err != nil {
		return nil, err
	}
	command := accountservice.ProvisionCommand{
		Input:       accountservice.ProvisionInput{Actor: input.Actor, IdempotencyKey: input.IdempotencyKey, Email: email.String()},
		Fingerprint: s.digest("temporary-password-provision:v1:" + email.String()),
	}
	// A committed retry needs no Argon2; the mutation still serializes racing first attempts.
	if previous, err := s.repo.FindTemporaryProvision(ctx, command); err != nil || previous != nil {
		return previous, err
	}
	secret, credential, err := s.prepareTemporary(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.repo.ProvisionTemporary(ctx, command, credential, s.cfg.TTL)
	if err != nil {
		return nil, err
	}
	if !result.Reused {
		result.Password = secret
	}
	return result, nil
}

func (s *TemporaryPasswordService) Reissue(ctx context.Context, input TemporaryReissueInput) (*TemporaryIssueResult, error) {
	if !s.cfg.Enabled {
		return nil, domain.ErrTemporaryPasswordDisabled
	}
	if input.Actor.Validate() != nil || !accountdomain.ValidUserID(input.UserID) || input.Actor.UserID == input.UserID || !accountdomain.ValidUserID(accountdomain.UserID(input.IdempotencyKey)) {
		return nil, accountdomain.ErrProvisionConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.limitIssue(ctx, input.Actor.UserID); err != nil {
		return nil, err
	}
	if previous, err := s.repo.FindTemporaryReissue(ctx, input); err != nil || previous != nil {
		return previous, err
	}
	secret, credential, err := s.prepareTemporary(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.repo.ReissueTemporary(ctx, input, credential, s.cfg.TTL, s.cfg.ReissueCooldown)
	if err != nil {
		return nil, err
	}
	if !result.Reused {
		result.Password = secret
	}
	return result, nil
}

func (s *TemporaryPasswordService) prepareTemporary(ctx context.Context) (string, domain.TemporaryCredential, error) {
	secret, err := temporarySecret()
	if err != nil {
		return "", domain.TemporaryCredential{}, err
	}
	hash, err := s.hash.GenerateHash(ctx, []byte(secret))
	if err != nil {
		return "", domain.TemporaryCredential{}, err
	}
	return secret, domain.TemporaryCredential{PasswordHash: hash, SecretDigest: resetDigest("temporary-password-secret:v1:" + secret)}, nil
}

func (s *TemporaryPasswordService) limitIssue(ctx context.Context, actor accountdomain.UserID) error {
	if err := s.limit(ctx, "temporary-password-issue-actor:"+string(actor), s.cfg.IssueActorAttemptsPerMinute); err != nil {
		return err
	}
	return s.limit(ctx, "temporary-password-issue-project", s.cfg.IssueProjectAttemptsPerMinute)
}

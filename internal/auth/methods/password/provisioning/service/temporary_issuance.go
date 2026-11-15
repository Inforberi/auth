package service

import (
	"context"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
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
	command := accountprovisioning.ProvisionCommand{
		Input:       accountprovisioning.ProvisionInput{Actor: input.Actor, IdempotencyKey: input.IdempotencyKey, Email: email.String()},
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
	ttl := s.cfg.TTL
	if s.cfg.TTLSource != nil {
		ttl, err = s.cfg.TTLSource(ctx)
		if err != nil {
			return nil, err
		}
	}
	result, err := s.repo.ProvisionTemporary(ctx, command, credential, ttl)
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
	ttl, cooldown := s.cfg.TTL, s.cfg.ReissueCooldown
	if s.cfg.ReissuePolicySource != nil {
		ttl, cooldown, err = s.cfg.ReissuePolicySource(ctx)
		if err != nil {
			return nil, err
		}
	}
	result, err := s.repo.ReissueTemporary(ctx, input, credential, ttl, cooldown)
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
	return secret, domain.TemporaryCredential{PasswordHash: hash, SecretDigest: passwordservice.TokenDigest("temporary-password-secret:v1:" + secret)}, nil
}

func (s *TemporaryPasswordService) limitIssue(ctx context.Context, actor accountdomain.UserID) error {
	actorLimit, projectLimit := s.cfg.IssueActorAttemptsPerMinute, s.cfg.IssueProjectAttemptsPerMinute
	if s.cfg.BudgetSource != nil {
		var err error
		actorLimit, projectLimit, _, err = s.cfg.BudgetSource(ctx)
		if err != nil {
			return err
		}
	}
	if err := s.limit(ctx, "temporary-password-issue-actor:"+string(actor), actorLimit); err != nil {
		return err
	}
	return s.limit(ctx, "temporary-password-issue-project", projectLimit)
}

type PreparedTemporaryPassword struct {
	Email, Fingerprint string
	Credential         domain.TemporaryCredential
	TTL, Cooldown      time.Duration
	secret             string
}

func (p PreparedTemporaryPassword) Reveal(result *TemporaryIssueResult) {
	if !result.Reused {
		result.Password = p.secret
	}
}

func (s *TemporaryPasswordService) PreparePlatformTemporary(ctx context.Context, actor accountdomain.UserID, rawEmail string) (PreparedTemporaryPassword, error) {
	if !s.cfg.Enabled {
		return PreparedTemporaryPassword{}, domain.ErrTemporaryPasswordDisabled
	}
	email, err := accountdomain.NewEmail(rawEmail)
	if err != nil {
		return PreparedTemporaryPassword{}, err
	}
	if err := s.limitIssue(ctx, actor); err != nil {
		return PreparedTemporaryPassword{}, err
	}
	ttl := s.cfg.TTL
	if s.cfg.TTLSource != nil {
		ttl, err = s.cfg.TTLSource(ctx)
		if err != nil {
			return PreparedTemporaryPassword{}, err
		}
	}
	secret, credential, err := s.prepareTemporary(ctx)
	if err != nil {
		return PreparedTemporaryPassword{}, err
	}
	return PreparedTemporaryPassword{
		Email: email.String(), Fingerprint: s.digest("temporary-password-provision:v1:" + email.String()),
		Credential: credential, TTL: ttl, secret: secret,
	}, nil
}

func (s *TemporaryPasswordService) PreparePlatformReissue(ctx context.Context, actor accountdomain.UserID) (PreparedTemporaryPassword, error) {
	if !s.cfg.Enabled {
		return PreparedTemporaryPassword{}, domain.ErrTemporaryPasswordDisabled
	}
	if err := s.limitIssue(ctx, actor); err != nil {
		return PreparedTemporaryPassword{}, err
	}
	ttl, cooldown := s.cfg.TTL, s.cfg.ReissueCooldown
	if s.cfg.ReissuePolicySource != nil {
		var err error
		ttl, cooldown, err = s.cfg.ReissuePolicySource(ctx)
		if err != nil {
			return PreparedTemporaryPassword{}, err
		}
	}
	secret, credential, err := s.prepareTemporary(ctx)
	return PreparedTemporaryPassword{Credential: credential, TTL: ttl, Cooldown: cooldown, secret: secret}, err
}

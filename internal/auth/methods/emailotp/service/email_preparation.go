package service

import (
	"context"
	"errors"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

const emailPreparationPurpose = "mfa-email-prepare:"

type EmailPreparationConfig struct {
	TTL, ResendInterval                       time.Duration
	RequestsPerMinute, ConfirmationsPerMinute int
}

type emailPreparationRepository interface {
	IssueEmailPreparation(context.Context, mfaservice.Proof, string, domain.Challenge) (time.Time, error)
	ConfirmEmailPreparation(context.Context, mfaservice.Proof, string, string, string) (*ReauthenticatedSession, error)
}

// EmailPreparation proves channel possession; it does not enable MFA or issue a login session.
type EmailPreparation struct {
	repo   emailPreparationRepository
	cipher cipher
	limits limiter
	tokens tokens
	cfg    EmailPreparationConfig
}

func NewEmailPreparation(repo emailPreparationRepository, cipher cipher, limits limiter, tokens tokens, cfg EmailPreparationConfig) (*EmailPreparation, error) {
	if repo == nil || cipher == nil || limits == nil || tokens == nil || cfg.TTL < time.Minute || cfg.TTL > 5*time.Minute || cfg.ResendInterval < time.Second || cfg.ResendInterval >= cfg.TTL || cfg.RequestsPerMinute < 1 || cfg.ConfirmationsPerMinute < 1 {
		return nil, errors.New("invalid email factor preparation configuration")
	}
	return &EmailPreparation{repo: repo, cipher: cipher, limits: limits, tokens: tokens, cfg: cfg}, nil
}

func (s *EmailPreparation) admit(ctx context.Context, proof mfaservice.Proof, ip string, confirm bool) error {
	phase, userCount, projectCount, userWindow := "request", 3, s.cfg.RequestsPerMinute, 15*time.Minute
	if confirm {
		phase, userCount, projectCount, userWindow = "confirm", 5, s.cfg.ConfirmationsPerMinute, time.Minute
	}
	type budget struct {
		key    string
		count  int
		window time.Duration
	}
	budgets := []budget{
		{phase + ":ip:" + ip, 10, time.Minute},
		{phase + ":user:" + string(proof.UserID), userCount, userWindow},
		{phase + ":project", projectCount, time.Minute},
	}
	if !confirm {
		budgets = append(budgets, budget{"request:cooldown:" + string(proof.UserID), 1, s.cfg.ResendInterval})
	}
	for _, budget := range budgets {
		ok, err := s.limits.Allow(ctx, s.cipher.Digest(emailPreparationPurpose+budget.key), budget.count, budget.window)
		if err != nil {
			return err
		}
		if !ok {
			return domain.ErrLimited
		}
	}
	return nil
}

func (s *EmailPreparation) Request(ctx context.Context, proof mfaservice.Proof, input, ip string) (*RequestedCode, error) {
	if err := proof.Validate(); err != nil {
		return nil, err
	}
	email, err := accountdomain.NewEmail(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.admit(ctx, proof, ip, false); err != nil {
		return nil, err
	}
	result, challenge, err := prepareCode(s.cipher, s.tokens, s.cfg.TTL, email.String(), "подготовки почтового фактора", emailPreparationPurpose)
	if err != nil {
		return nil, err
	}
	expires, err := s.repo.IssueEmailPreparation(ctx, proof, email.String(), challenge)
	if err != nil {
		return nil, err
	}
	result.ExpiresAt = expires
	return result, nil
}

package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type CompleteLoginInput struct {
	Token, Binding, Code string
	Recovery             bool
	UserAgent, IP        string
}

type LoginCompletion struct {
	AllowPrimary                     func(method, issuer string) bool
	Digest, BindingHash, SessionHash string
	UserAgent, IP                    string
	SessionTTL, AbsoluteSessionTTL   time.Duration
	AdminIdleTimeout                 time.Duration
	AdminAbsoluteTTL                 time.Duration
	AdminActivityInterval            time.Duration
}

type LoginCommit struct {
	UserID      accountdomain.UserID
	ExpiresAt   time.Time
	MFAVerified time.Time
}

type LoginSession struct {
	Token       string `json:"-"`
	UserID      accountdomain.UserID
	ExpiresAt   time.Time
	MFAVerified time.Time
}

func (s *Login) Complete(ctx context.Context, input CompleteLoginInput) (*LoginSession, error) {
	if !validLoginToken(input.Token) || !validLoginToken(input.Binding) ||
		(input.Recovery && !domain.ValidRecoveryCode(input.Code)) || (!input.Recovery && !domain.ValidCode(input.Code)) ||
		len(input.UserAgent) > 512 || len(input.IP) > 64 {
		return nil, domain.ErrInvalidCode
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// User attempts are enforced by the locked SQL challenge; wrong browser bindings cannot burn them.
	if err := s.admitLogin(ctx, "complete", input.Token+":"+input.Binding, input.IP, 5); err != nil {
		return nil, err
	}
	digest, binding := s.cipher.Digest("login:"+input.Token), s.cipher.Digest("browser:"+input.Binding)
	user, err := s.repo.FindLoginOwner(ctx, digest, binding)
	if err != nil {
		return nil, err
	}
	// This counter spans all primary logins: replacing a challenge cannot reset guessing admission.
	if err := admitFactorUser(ctx, s.cipher, s.limit, s.cfg.UserLimitPerMinute, user); err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	// The repository owns the challenge's user, not a caller-supplied UUID.
	result, err := s.repo.CompleteLogin(ctx, LoginCompletion{
		AllowPrimary: s.cfg.AllowPrimary,
		Digest:       digest, BindingHash: binding,
		SessionHash: s.tokens.Hash(raw), UserAgent: input.UserAgent, IP: input.IP,
		SessionTTL: s.cfg.SessionTTL, AbsoluteSessionTTL: s.cfg.AbsoluteSessionTTL,
		AdminIdleTimeout:      s.cfg.AdminIdleTimeout,
		AdminAbsoluteTTL:      s.cfg.AdminAbsoluteTTL,
		AdminActivityInterval: s.cfg.AdminActivityInterval,
	}, func(user accountdomain.UserID) (Check, string) {
		digest := ""
		if input.Recovery {
			digest = s.cipher.Digest("recovery:" + string(user) + ":" + input.Code)
		}
		return factorCheck(s.cipher, s.code, user, input.Code), digest
	})
	if err != nil {
		return nil, err
	}
	return &LoginSession{Token: raw, UserID: result.UserID, ExpiresAt: result.ExpiresAt, MFAVerified: result.MFAVerified}, nil
}

func (s *Login) admitLogin(ctx context.Context, purpose, subject, ip string, count int) error {
	return admitLogin(ctx, s.cipher, s.limit, s.cfg, purpose, subject, ip, count)
}

func admitFactorUser(ctx context.Context, cipher Cipher, limit Limiter, operations int, user accountdomain.UserID) error {
	for _, budget := range []struct {
		key   string
		count int
	}{
		{cipher.Digest("user:" + string(user)), operations},
		{cipher.Digest("login:factor-user:" + string(user)), 5},
	} {
		allowed, err := limit.Allow(ctx, budget.key, budget.count, time.Minute)
		if err != nil {
			return domain.ErrUnavailable
		}
		if !allowed {
			return domain.ErrLimited
		}
	}
	return nil
}

func admitLogin(ctx context.Context, cipher Cipher, limit Limiter, cfg LoginConfig, purpose, subject, ip string, count int) error {
	subjectKey := "login:" + purpose + ":subject:" + cipher.Digest(subject)
	if purpose == "start" {
		subjectKey = cipher.Digest("user:" + subject)
	}
	for _, budget := range []struct {
		key   string
		count int
	}{
		{subjectKey, count},
		{"login:ip:" + cipher.Digest(ip), cfg.IPLimitPerMinute},
		{"project", cfg.GlobalLimitPerMinute},
	} {
		allowed, err := limit.Allow(ctx, budget.key, budget.count, time.Minute)
		if err != nil {
			return domain.ErrUnavailable
		}
		if !allowed {
			return domain.ErrLimited
		}
	}
	return nil
}

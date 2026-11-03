package service

import (
	"context"
	"net/netip"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func (s *EmailLogin) Complete(ctx context.Context, input mfalogin.CompleteLoginInput) (*mfalogin.LoginSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	attempt, err := s.prepare(ctx, input, false)
	if err != nil {
		return nil, err
	}
	raw, err := s.tokens.GenerateToken()
	if err != nil {
		return nil, err
	}
	result, err := s.repo.CompleteLogin(ctx, mfalogin.LoginCompletion{
		Email: attempt.Email, Digest: attempt.Digest, BindingHash: attempt.BindingHash,
		SessionHash: s.tokens.Hash(raw), UserAgent: input.UserAgent, IP: input.IP,
		AllowPrimary: s.cfg.AllowPrimary, SessionTTL: s.cfg.SessionTTL, AbsoluteSessionTTL: s.cfg.AbsoluteSessionTTL,
		AdminIdleTimeout: s.cfg.AdminIdleTimeout, AdminAbsoluteTTL: s.cfg.AdminAbsoluteTTL, AdminActivityInterval: s.cfg.AdminActivityInterval,
	}, nil)
	if err != nil {
		return nil, err
	}
	return &mfalogin.LoginSession{Token: raw, UserID: result.UserID, ExpiresAt: result.ExpiresAt, MFAVerified: result.MFAVerified}, nil
}

func (s *EmailLogin) PrepareNativeCompletion(ctx context.Context, input mfalogin.CompleteLoginInput) (mfalogin.NativeAttempt, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.prepare(ctx, input, true)
}

func (s *EmailLogin) prepare(ctx context.Context, input mfalogin.CompleteLoginInput, native bool) (mfalogin.NativeAttempt, error) {
	var attempt mfalogin.NativeAttempt
	if !domain.ValidBinding(input.Token) || !domain.ValidBinding(input.Binding) || !domain.ValidCode(input.Code) || input.Recovery || len(input.UserAgent) > 512 || len(input.IP) > 64 {
		return attempt, mfadomain.ErrInvalidCode
	}
	address, err := netip.ParseAddr(input.IP)
	if err != nil || address.Zone() != "" {
		return attempt, mfadomain.ErrInvalidCode
	}
	if err := s.admit(ctx, "complete", input.Token+":"+input.Binding, address.Unmap().String(), 5); err != nil {
		return attempt, err
	}
	attempt.Digest, attempt.BindingHash = s.identifiers(input.Token, input.Binding, native)
	find := s.repo.FindLoginOwner
	if native {
		find = s.repo.FindNativeLoginOwner
	}
	user, err := find(ctx, attempt.Digest, attempt.BindingHash)
	if err != nil {
		return attempt, err
	}
	allowed, err := s.limits.AllowAll(ctx, []mfaservice.Budget{
		{Key: s.mfa.Digest("user:" + string(user)), Count: s.cfg.UserLimitPerMinute},
		{Key: s.mfa.Digest("login:factor-user:" + string(user)), Count: 5},
	})
	if err != nil {
		return attempt, mfadomain.ErrUnavailable
	}
	if !allowed {
		return attempt, mfadomain.ErrLimited
	}
	attempt.UserID, attempt.AllowPrimary = user, s.cfg.AllowPrimary
	attempt.Email = &mfalogin.EmailCodeProof{
		Digest:   s.mail.Digest(emailLoginPurpose + "binding:" + input.Token),
		Verifier: s.mail.Digest(emailLoginPurpose + "code:" + input.Token + ":" + input.Code),
	}
	return attempt, nil
}

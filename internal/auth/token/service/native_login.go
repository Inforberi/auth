package service

import (
	"context"
	"errors"
	"net/netip"
	"time"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type NativeMFA interface {
	StartNative(context.Context, mfaservice.PrimaryProof, mfaservice.NativeTarget, string) (*mfaservice.LoginChallenge, error)
	PrepareNativeCompletion(context.Context, mfaservice.CompleteLoginInput) (mfaservice.NativeAttempt, error)
}

type NativeLogin struct {
	tokens *Service
	mfa    NativeMFA
}

type NativeLoginResult struct {
	Tokens    *RefreshResult
	Challenge *mfaservice.LoginChallenge
}

type NativeMFAParams struct {
	Attempt                         mfaservice.NativeAttempt
	Policy                          NativePolicy
	LedgerVerifier, RefreshVerifier string `json:"-"`
	UserAgent, IP                   string
}

func NewNativeLogin(tokens *Service, mfa NativeMFA) (*NativeLogin, error) {
	if tokens == nil || tokens.native == nil || mfa == nil {
		return nil, authjwt.ErrConfiguration
	}
	return &NativeLogin{tokens: tokens, mfa: mfa}, nil
}

func (s *NativeLogin) Begin(ctx context.Context, input NativeInput) (*NativeLoginResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tokens, err := s.tokens.IssueNative(ctx, input)
	if !errors.Is(err, sessiondomain.ErrMFARequired) {
		if err != nil {
			return nil, err
		}
		return &NativeLoginResult{Tokens: tokens}, nil
	}
	challenge, err := s.mfa.StartNative(ctx, input.Proof, mfaservice.NativeTarget{Audience: input.Audience, Scope: input.Scope}, input.IP)
	if err != nil {
		return nil, err
	}
	return &NativeLoginResult{Challenge: challenge}, nil
}

func (s *NativeLogin) Complete(ctx context.Context, input mfaservice.CompleteLoginInput) (*RefreshResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(input.IP)
	if err != nil || ip.Zone() != "" {
		return nil, domain.ErrInvalidRequest
	}
	input.IP = ip.Unmap().String()
	select {
	case s.tokens.admission <- struct{}{}:
	default:
		return nil, authjwt.ErrBusy
	}
	defer func() { <-s.tokens.admission }()
	// Bound random-token subject keys before MFA admission allocates them or queries SQL.
	if err := s.tokens.limiter.AllowCredentialLookup(ctx, input.IP); err != nil {
		return nil, err
	}
	attempt, err := s.mfa.PrepareNativeCompletion(ctx, input)
	if err != nil {
		return nil, err
	}
	if err := s.tokens.limiter.AllowNative(ctx, attempt.UserID, input.IP); err != nil {
		return nil, err
	}
	credentials, err := s.tokens.newNativeCredentials()
	if err != nil {
		return nil, err
	}
	p := NativeMFAParams{Attempt: attempt, Policy: *s.tokens.native, LedgerVerifier: credentials.ledgerVerifier, RefreshVerifier: credentials.refreshVerifier, UserAgent: input.UserAgent, IP: input.IP}
	result, err := s.tokens.repo.CompleteNativeMFA(ctx, p, func(target mfaservice.NativeTarget) (string, error) {
		resource, _, err := s.tokens.requestedResource(target.Audience, target.Scope)
		return resource.mode, err
	}, s.tokens.signSession)
	if err != nil {
		return nil, err
	}
	if result == nil || result.ExchangeResult == nil || result.SignedToken == nil || result.Raw == "" {
		return nil, domain.ErrUnavailable
	}
	result.RefreshToken = credentials.refresh
	return result, nil
}

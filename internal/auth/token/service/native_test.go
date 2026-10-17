package service

import (
	"context"
	"errors"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/signing"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func testNativePolicy() NativePolicy {
	return NativePolicy{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour, Sessions: sessionservice.Config{SessionTTL: 7 * 24 * time.Hour, AbsoluteSessionTTL: 14 * 24 * time.Hour, AdminIdleTimeout: 30 * time.Minute, AdminAbsoluteTTL: 12 * time.Hour, AdminActivityInterval: time.Minute}}
}

type nativeRepo struct {
	exchangeRepo
	params NativeParams
	calls  int
	err    error
}

func (r *nativeRepo) IssueNative(ctx context.Context, p NativeParams, sign func(context.Context, ExchangeInput, SessionProof) (*signing.SignedToken, error)) (*RefreshResult, error) {
	r.calls++
	r.params = p
	if r.err != nil {
		return nil, r.err
	}
	input := ExchangeInput{Actor: accessservice.Principal{UserID: p.Input.Proof.UserID, TokenHash: p.LedgerVerifier}, SessionID: "22222222-2222-4222-8222-222222222222", Audience: p.Input.Audience, Scope: p.Input.Scope}
	proof := SessionProof{AuthVersion: p.Input.Proof.AuthVersion, VerifiedAt: p.Input.Proof.VerifiedAt, Method: "password", Now: time.Now().UTC(), Deadline: time.Now().Add(p.Policy.IdleTTL)}
	issued, err := sign(ctx, input, proof)
	if err != nil {
		return nil, err
	}
	return &RefreshResult{ExchangeResult: &ExchangeResult{SignedToken: issued, Audience: input.Audience, Scope: input.Scope, Mode: p.Mode}, RefreshExpiresAt: proof.Now.Add(p.Policy.AbsoluteTTL)}, nil
}

func nativeServiceFixture(t *testing.T) (*Service, *nativeRepo, *exchangeSigner, *exchangeLimiter, NativeInput) {
	t.Helper()
	svc, _, signer, limiter, exchange := exchangeFixture(t)
	policy := testNativePolicy()
	svc.native = &policy
	repo := &nativeRepo{}
	svc.repo = repo
	return svc, repo, signer, limiter, NativeInput{Proof: mfaservice.PrimaryProof{UserID: exchange.Actor.UserID, AuthVersion: 4, Method: "password", Reference: "verified hash", VerifiedAt: time.Now().UTC()}, Audience: exchange.Audience, Scope: exchange.Scope, IP: exchange.IP, UserAgent: "native fixture"}
}

func TestNativeInitialCredentialBoundary(t *testing.T) {
	svc, repo, signer, _, input := nativeServiceFixture(t)
	result, err := svc.IssueNative(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := domain.RefreshVerifier(result.RefreshToken)
	if err != nil || verifier != repo.params.RefreshVerifier || verifier == repo.params.LedgerVerifier {
		t.Fatal("ledger secret leaked or reused", err)
	}
	if repo.params.Input.IP != "192.0.2.1" || signer.claims.Scope != "orders.read orders.write" || signer.claims.AuthVersion != 4 || signer.claims.MFATime != nil || signer.claims.AuthTime != input.Proof.VerifiedAt.Unix() || input.Scope[0] != "orders.write" {
		t.Fatal("wrong initial claims or mutated input")
	}
}

func TestNativeAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Service, *nativeRepo, *exchangeLimiter, *NativeInput)
		want   error
	}{
		{"disabled", func(s *Service, _ *nativeRepo, _ *exchangeLimiter, _ *NativeInput) { s.native = nil }, domain.ErrNativeDisabled},
		{"admin", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) { i.Proof.Administrative = true }, domain.ErrInvalidRequest},
		{"email OTP not bound yet", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) {
			i.Proof.Method = "emailotp"
			i.Proof.Reference = "11111111-1111-4111-8111-111111111111"
		}, domain.ErrInvalidRequest},
		{"bad proof", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) { i.Proof.AuthVersion = 0 }, domain.ErrInvalidRequest},
		{"bad IP", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) { i.IP = "fe80::1%en0" }, domain.ErrInvalidRequest},
		{"bad audience", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) { i.Audience = "other" }, domain.ErrInvalidRequest},
		{"duplicate scope", func(_ *Service, _ *nativeRepo, _ *exchangeLimiter, i *NativeInput) {
			i.Scope = []accessdomain.PermissionKey{"orders.read", "orders.read"}
		}, domain.ErrForbidden},
		{"budget", func(_ *Service, _ *nativeRepo, l *exchangeLimiter, _ *NativeInput) { l.err = domain.ErrRateLimited }, domain.ErrRateLimited},
		{"busy", func(s *Service, _ *nativeRepo, _ *exchangeLimiter, _ *NativeInput) {
			for range cap(s.admission) {
				s.admission <- struct{}{}
			}
		}, authjwt.ErrBusy},
	} {
		t.Run(test.name, func(t *testing.T) {
			svc, repo, _, limiter, input := nativeServiceFixture(t)
			test.change(svc, repo, limiter, &input)
			if result, err := svc.IssueNative(t.Context(), input); result != nil || !errors.Is(err, test.want) || repo.calls != 0 {
				t.Fatal("unexpected issuance", err, repo.calls)
			}
		})
	}
	svc, repo, _, _, input := nativeServiceFixture(t)
	repo.err = sessiondomain.ErrMFARequired
	if result, err := svc.IssueNative(t.Context(), input); result != nil || !errors.Is(err, sessiondomain.ErrMFARequired) {
		t.Fatal("MFA bypass", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.IssueNative(ctx, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestNativePolicyCeilings(t *testing.T) {
	for _, change := range []func(*NativePolicy){
		func(p *NativePolicy) { p.IdleTTL = time.Second }, func(p *NativePolicy) { p.IdleTTL = 8 * 24 * time.Hour },
		func(p *NativePolicy) { p.AbsoluteTTL = 15 * 24 * time.Hour }, func(p *NativePolicy) { p.AbsoluteTTL = time.Minute },
		func(p *NativePolicy) { p.IdleTTL = time.Hour + 1 }, func(p *NativePolicy) { p.Sessions.AdminActivityInterval = 0 },
	} {
		p := testNativePolicy()
		change(&p)
		if err := p.Validate(); !errors.Is(err, authjwt.ErrConfiguration) {
			t.Fatal("bad policy accepted", err)
		}
	}
	if err := testNativePolicy().Validate(); err != nil {
		t.Fatal(err)
	}
}

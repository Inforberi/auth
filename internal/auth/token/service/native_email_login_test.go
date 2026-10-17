package service

import (
	"context"
	"errors"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	emailservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type nativeEmailStub struct {
	requests, confirmations int
	target                  mfaservice.NativeTarget
	result                  emailservice.NativeAuthentication
	err                     error
}

func (s *nativeEmailStub) RequestNative(_ context.Context, _, _ string, target mfaservice.NativeTarget) (*emailservice.RequestedCode, error) {
	s.requests++
	s.target = target
	return &emailservice.RequestedCode{}, s.err
}

func (s *nativeEmailStub) AuthenticateNative(context.Context, emailservice.ConfirmInput) (*emailservice.NativeAuthentication, error) {
	s.confirmations++
	if s.err != nil {
		return nil, s.err
	}
	return &s.result, nil
}

func TestNativeEmailCoordinator(t *testing.T) {
	tokens, repo, signer, limiter, input := nativeServiceFixture(t)
	factor := &nativeMFAStub{}
	login, err := NewNativeLogin(tokens, factor)
	if err != nil {
		t.Fatal(err)
	}
	email := &nativeEmailStub{result: emailservice.NativeAuthentication{
		Proof: mfaservice.PrimaryProof{
			UserID: input.Proof.UserID, AuthVersion: 4, Method: "emailotp", Reference: "11111111-1111-4111-8111-111111111111", VerifiedAt: time.Now().UTC(),
		},
		Target: mfaservice.NativeTarget{Audience: "orders", Scope: []accessdomain.PermissionKey{"orders.read"}},
	}}
	svc, err := NewNativeEmailLogin(login, email)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Request(t.Context(), "user@example.test", input.IP, "other", input.Scope); err == nil || email.requests != 0 {
		t.Fatal("unconfigured audience reached mail", err)
	}
	if _, err := svc.Request(t.Context(), "user@example.test", input.IP, "orders", input.Scope); err != nil || email.requests != 1 || email.target.Scope[0] != "orders.read" {
		t.Fatal("request target not canonical", err)
	}
	confirm := emailservice.ConfirmInput{IP: input.IP}
	result, err := svc.Confirm(t.Context(), confirm)
	if err != nil || result.Tokens == nil || result.Challenge != nil || signer.claims.Methods[0] != "emailotp" || signer.claims.MFATime != nil || repo.params.Input.Scope[0] != "orders.read" {
		t.Fatal("incorrect email proof/target/assurance", err)
	}
	repo.err = sessiondomain.ErrMFARequired
	result, err = svc.Confirm(t.Context(), confirm)
	if err != nil || result.Tokens != nil || result.Challenge == nil || factor.starts != 1 {
		t.Fatal("email login bypassed MFA", err)
	}
	limiter.err = domain.ErrRateLimited
	previous := email.confirmations
	if _, err := svc.Confirm(t.Context(), confirm); !errors.Is(err, domain.ErrRateLimited) || email.confirmations != previous {
		t.Fatal("random code bypassed prelookup budget", err)
	}
	if _, err := NewNativeEmailLogin(nil, email); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal(err)
	}
}

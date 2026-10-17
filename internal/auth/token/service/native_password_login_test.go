package service

import (
	"context"
	"errors"
	"testing"

	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
)

type nativePrimaryStub struct {
	proof mfaservice.PrimaryProof
	input passwordservice.LoginInput
	err   error
	calls int
}

func (s *nativePrimaryStub) Authenticate(_ context.Context, input passwordservice.LoginInput) (mfaservice.PrimaryProof, error) {
	s.calls++
	s.input = input
	return s.proof, s.err
}

func TestNativePasswordUsesSharedPrimary(t *testing.T) {
	tokens, repo, _, _, base := nativeServiceFixture(t)
	factor := &nativeMFAStub{}
	login, err := NewNativeLogin(tokens, factor)
	if err != nil {
		t.Fatal(err)
	}
	primary := &nativePrimaryStub{proof: base.Proof}
	svc, err := NewNativePasswordLogin(login, primary)
	if err != nil {
		t.Fatal(err)
	}
	input := NativePasswordInput{Email: "user@example.test", Password: "Password12345", Audience: base.Audience, Scope: base.Scope, IP: base.IP, UserAgent: base.UserAgent}
	result, err := svc.Login(t.Context(), input)
	if err != nil || result.Tokens == nil || primary.calls != 1 || repo.params.Input.Proof != base.Proof || primary.input.Email != input.Email || primary.input.IP != input.IP {
		t.Fatal(err)
	}
	repo.err = sessiondomain.ErrMFARequired
	result, err = svc.Login(t.Context(), input)
	if err != nil || result.Challenge == nil || result.Tokens != nil || factor.starts != 1 {
		t.Fatal("MFA bypass", err)
	}
	primary.err = domain.ErrUnavailable
	before := repo.calls
	if result, err := svc.Login(t.Context(), input); result != nil || !errors.Is(err, primary.err) || repo.calls != before {
		t.Fatal("primary failure issued tokens", err)
	}
	primary.err = nil
	before = primary.calls
	input.Audience = "unknown"
	if result, err := svc.Login(t.Context(), input); result != nil || !errors.Is(err, domain.ErrInvalidRequest) || primary.calls != before {
		t.Fatal("invalid resource reached password hashing", err)
	}
	if _, err := NewNativePasswordLogin(nil, primary); err == nil {
		t.Fatal("nil coordinator accepted")
	}
	if _, err := NewNativePasswordLogin(login, nil); err == nil {
		t.Fatal("nil primary accepted")
	}
}

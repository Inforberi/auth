package service

import (
	"context"
	"errors"
	"testing"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessiondomain "github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/token/domain"
	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

type nativeMFAStub struct {
	starts, prepares int
	err              error
}

func (s *nativeMFAStub) StartNative(_ context.Context, _ mfaservice.PrimaryProof, _ mfaservice.NativeTarget, _ string) (*mfaservice.LoginChallenge, error) {
	s.starts++
	return &mfaservice.LoginChallenge{}, s.err
}

func (s *nativeMFAStub) PrepareNativeCompletion(_ context.Context, _ mfaservice.CompleteLoginInput) (mfaservice.NativeAttempt, error) {
	s.prepares++
	return mfaservice.NativeAttempt{}, s.err
}

func TestNativeCoordinatorOutputs(t *testing.T) {
	tokens, repo, _, _, input := nativeServiceFixture(t)
	factor := &nativeMFAStub{}
	login, err := NewNativeLogin(tokens, factor)
	if err != nil {
		t.Fatal(err)
	}
	result, err := login.Begin(t.Context(), input)
	if err != nil || result.Tokens == nil || result.Challenge != nil || factor.starts != 0 {
		t.Fatal("ordinary login unexpectedly used MFA", err)
	}
	repo.err = sessiondomain.ErrMFARequired
	result, err = login.Begin(t.Context(), input)
	if err != nil || result.Tokens != nil || result.Challenge == nil || factor.starts != 1 {
		t.Fatal("partial login issued credentials", err)
	}
	factor.err = domain.ErrUnavailable
	if result, err := login.Begin(t.Context(), input); result != nil || !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("MFA outage bypassed", err)
	}
}

func TestNativeCoordinatorAdmission(t *testing.T) {
	tokens, _, _, limiter, _ := nativeServiceFixture(t)
	factor := &nativeMFAStub{}
	login, err := NewNativeLogin(tokens, factor)
	if err != nil {
		t.Fatal(err)
	}
	input := mfaservice.CompleteLoginInput{IP: "192.0.2.1"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := login.Complete(ctx, input); !errors.Is(err, context.Canceled) || factor.prepares != 0 {
		t.Fatal(err)
	}
	for range cap(tokens.admission) {
		tokens.admission <- struct{}{}
	}
	if _, err := login.Complete(t.Context(), input); !errors.Is(err, authjwt.ErrBusy) || factor.prepares != 0 {
		t.Fatal("unbounded completion", err)
	}
	for range cap(tokens.admission) {
		<-tokens.admission
	}
	limiter.err = domain.ErrRateLimited
	if _, err := login.Complete(t.Context(), input); !errors.Is(err, domain.ErrRateLimited) || factor.prepares != 0 {
		t.Fatal("random challenge bypassed prelookup budget", err)
	}
	if _, err := NewNativeLogin(nil, factor); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("nil issuer accepted", err)
	}
	tokens.native = nil
	if _, err := NewNativeLogin(tokens, factor); !errors.Is(err, authjwt.ErrConfiguration) {
		t.Fatal("disabled profile accepted", err)
	}
}

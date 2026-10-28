package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type mfaStarterStub struct {
	proof mfaservice.PrimaryProof
	calls int
	err   error
}

func (m *mfaStarterStub) Start(_ context.Context, p mfaservice.PrimaryProof, _ string) (*mfaservice.LoginChallenge, error) {
	m.proof = p
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &mfaservice.LoginChallenge{Token: "challenge", Binding: "browser", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestPrimaryLoginDispatch(t *testing.T) {
	for _, administrative := range []bool{false, true} {
		for _, failure := range []error{nil, domain.ErrMFARequired, domain.ErrSessionNotFound} {
			repo, tokens, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
			tokens.On("GenerateToken").Return("raw", nil)
			tokens.On("Hash", "raw").Return("hash")
			clock.On("NowUTC").Return(now)
			repo.On("CreateSession", mock.Anything, mock.MatchedBy(func(p CreateSessionParams) bool {
				return p.PrimaryProof != nil && p.PrimaryProof.Administrative == administrative
			})).Return(now.Add(cfg.SessionTTL), failure)
			mfa := &mfaStarterStub{}
			proof := mfaservice.PrimaryProof{UserID: "user", AuthVersion: 7, Method: "password", Reference: "compared-hash", VerifiedAt: time.Now(), Administrative: administrative}
			result, err := NewLogin(New(clock, repo, tokens, cfg), mfa).BeginLogin(context.Background(), proof, "agent", "ip")
			if errors.Is(failure, domain.ErrMFARequired) {
				if err != nil || result.Challenge == nil || result.RawToken != "" || mfa.proof != proof || mfa.calls != 1 {
					t.Fatal("MFA dispatch", result, err)
				}
			} else if mfa.calls != 0 || !errors.Is(err, failure) {
				t.Fatal("unexpected MFA dispatch", err)
			}
		}
	}
}

func TestAdministrativeLoginCannotBypassRepositoryMFARequirement(t *testing.T) {
	for _, plain := range []bool{false, true} {
		repo, tokens, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
		tokens.On("GenerateToken").Return("raw", nil)
		tokens.On("Hash", "raw").Return("hash")
		clock.On("NowUTC").Return(now)
		repo.On("CreateSession", mock.Anything, mock.Anything).Return(time.Time{}, domain.ErrMFARequired)
		sessions := New(clock, repo, tokens, cfg)
		var err error
		proof := mfaservice.PrimaryProof{Administrative: true, Method: "password"}
		if plain {
			_, err = sessions.BeginLogin(context.Background(), proof, "", "")
		} else {
			_, err = NewLogin(sessions, nil).BeginLogin(context.Background(), proof, "", "")
		}
		if !errors.Is(err, domain.ErrMFARequired) {
			t.Fatal("missing MFA adapter bypassed repository requirement", err)
		}
	}
}

package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	mfalogin "github.com/Inforberi/financial-intelligence/internal/auth/mfa/login/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type mfaStarterStub struct {
	proof mfaservice.PrimaryProof
	calls int
	err   error
}

func (m *mfaStarterStub) Start(_ context.Context, p mfaservice.PrimaryProof, _ string) (*mfalogin.LoginChallenge, error) {
	m.proof = p
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &mfalogin.LoginChallenge{Token: "challenge", Binding: "browser", ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestPrimaryLoginDispatch(t *testing.T) {
	for _, administrative := range []bool{false, true} {
		for _, failure := range []error{nil, domain.ErrMFARequired, domain.ErrSessionNotFound} {
			repo, tokens, clock := &mockRepo{}, &mockTokenHash{}, &mockClock{}
			tokens.On("GenerateToken").Return("raw", nil)
			tokens.On("Hash", "raw").Return("hash")
			clock.On("NowUTC").Return(now)
			repo.On("CreateSession", mock.Anything, mock.MatchedBy(func(p sessionservice.CreateSessionParams) bool {
				return p.PrimaryProof != nil && p.PrimaryProof.Administrative == administrative
			})).Return(now.Add(cfg.SessionTTL), failure)
			mfa := &mfaStarterStub{}
			proof := mfaservice.PrimaryProof{UserID: "user", AuthVersion: 7, Method: "password", Reference: "compared-hash", VerifiedAt: time.Now(), Administrative: administrative}
			result, err := sessionservice.NewLogin(sessionservice.New(clock, repo, tokens, cfg), mfa).BeginLogin(context.Background(), proof, "agent", "ip")
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
		sessions := sessionservice.New(clock, repo, tokens, cfg)
		var err error
		proof := mfaservice.PrimaryProof{Administrative: true, Method: "password"}
		if plain {
			_, err = sessions.BeginLogin(context.Background(), proof, "", "")
		} else {
			_, err = sessionservice.NewLogin(sessions, nil).BeginLogin(context.Background(), proof, "", "")
		}
		if !errors.Is(err, domain.ErrMFARequired) {
			t.Fatal("missing MFA adapter bypassed repository requirement", err)
		}
	}
}

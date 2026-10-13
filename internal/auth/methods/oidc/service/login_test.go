package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/oidc/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type loginFixture struct {
	mu                            sync.Mutex
	issuer                        string
	state, binding                string
	flow                          domain.Flow
	consumed                      bool
	failure                       string
	proofs, resolutions, sessions int
	registration                  bool
	primary                       mfaservice.PrimaryProof
}

func (f *loginFixture) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*sessionservice.CreatedSession, error) {
	f.primary = proof
	return f.CreateSessionAtVersion(ctx, proof.UserID, agent, ip, proof.AuthVersion)
}

func (f *loginFixture) Allow(context.Context, string, int, int) (bool, error) {
	if f.failure == "limit" {
		return false, nil
	}
	if f.failure == "redis" {
		return false, errors.New("redis failed")
	}
	return true, nil
}

func (f *loginFixture) Save(_ context.Context, state, binding string, flow domain.Flow) error {
	f.state, f.binding, f.flow = state, binding, flow
	return nil
}

func (f *loginFixture) Consume(_ context.Context, state, binding string) (*domain.Flow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consumed || state != f.state || binding != f.binding {
		return nil, domain.ErrInvalidFlow
	}
	f.consumed = true
	return &f.flow, nil
}

func (f *loginFixture) AuthorizationURL(state string, flow domain.Flow) string {
	return "https://provider.example?state=" + state
}

func (f *loginFixture) Verify(context.Context, string, domain.Flow) (accountdomain.IdentityKey, error) {
	f.proofs++
	if f.failure == "proof" {
		return accountdomain.IdentityKey{}, domain.ErrInvalidFlow
	}
	issuer := f.issuer
	if issuer == "" {
		issuer = "https://oauth.telegram.org"
	}
	return accountdomain.IdentityKey{Issuer: issuer, Subject: "subject"}, nil
}

func (f *loginFixture) Resolve(_ context.Context, key accountdomain.IdentityKey, allow bool) (*accountdomain.User, error) {
	f.resolutions++
	f.registration = allow
	if f.failure == "account" {
		return nil, accountdomain.ErrIdentityUnavailable
	}
	return &accountdomain.User{ID: "owner", Status: accountdomain.StatusActive, AuthVersion: 7}, nil
}

func (f *loginFixture) CreateSessionAtVersion(_ context.Context, user accountdomain.UserID, ua, ip string, version int64) (*sessionservice.CreatedSession, error) {
	f.sessions++
	if user != "owner" || version != 7 || ua != "browser" || ip != "127.0.0.1" {
		return nil, errors.New("wrong session contract")
	}
	if f.failure == "session" {
		return nil, errors.New("session failed")
	}
	return &sessionservice.CreatedSession{RawToken: "session", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestLoginLifecycle(t *testing.T) {
	for _, issuer := range []string{"https://oauth.telegram.org", "https://accounts.google.com"} {
		t.Run(issuer, func(t *testing.T) { testLoginLifecycle(t, issuer) })
	}
}

func testLoginLifecycle(t *testing.T, issuer string) {
	for _, failure := range []string{"", "limit", "redis", "proof", "account", "session"} {
		t.Run("failure="+failure, func(t *testing.T) {
			f := &loginFixture{issuer: issuer}
			s := New(Config{Issuer: issuer, Enabled: true, RegistrationEnabled: true, IPLimit: 30, GlobalLimit: 1000}, f, f, f, f, tokengenerate.New(), nil)
			started, err := s.Start(t.Context(), "127.0.0.1")
			if err != nil || started.Binding != f.binding || f.flow.Nonce == f.flow.Verifier {
				t.Fatal(started, err)
			}
			f.failure = failure
			input := CallbackInput{Code: "code", State: f.state, Binding: f.binding, UserAgent: "browser", IP: "127.0.0.1"}
			bad := input
			bad.Binding = strings.Repeat("A", 43)
			if _, err := s.Callback(t.Context(), bad); err == nil || f.consumed {
				t.Fatal("bad binding consumed flow", err)
			}
			result, err := s.Callback(t.Context(), input)
			if failure == "" {
				if err != nil || result.Session.RawToken != "session" || result.Linked || !f.registration {
					t.Fatal(result, err)
				}
				if f.primary.Method != "oidc" || f.primary.Reference != "subject" || f.primary.Issuer != issuer || f.primary.VerifiedAt.IsZero() {
					t.Fatal("provider proof lost", f.primary)
				}
				if _, err := s.Callback(t.Context(), input); !errors.Is(err, domain.ErrInvalidFlow) {
					t.Fatal("replayed callback accepted", err)
				}
			} else if err == nil || result != nil {
				t.Fatal("failure created session", result, err)
			}
			if (failure == "proof" && f.resolutions != 0) || ((failure == "account" || failure == "proof" || failure == "redis" || failure == "limit") && f.sessions != 0) {
				t.Fatal("failed gate reached next phase")
			}
		})
	}
}

func TestConcurrentCallbacks(t *testing.T) {
	f := &loginFixture{}
	s := New(Config{Issuer: "https://oauth.telegram.org", Enabled: true, IPLimit: 30, GlobalLimit: 1000}, f, f, f, f, tokengenerate.New(), nil)
	if _, err := s.Start(t.Context(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := s.Callback(t.Context(), CallbackInput{Code: "code", State: f.state, Binding: f.binding, UserAgent: "browser", IP: "127.0.0.1"})
			if err != nil && !errors.Is(err, domain.ErrInvalidFlow) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if f.sessions != 1 || f.proofs != 1 || f.resolutions != 1 || f.registration {
		t.Fatal("callback not single-use or registration policy ignored")
	}
}

func TestDisabledLogin(t *testing.T) {
	s := New(Config{}, nil, nil, nil, nil, nil, nil)
	if _, err := s.Start(t.Context(), "ip"); !errors.Is(err, domain.ErrDisabled) {
		t.Fatal(err)
	}
	if _, err := s.Callback(t.Context(), CallbackInput{}); !errors.Is(err, domain.ErrDisabled) {
		t.Fatal(err)
	}
}

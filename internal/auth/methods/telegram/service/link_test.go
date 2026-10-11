package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/telegram/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type managementFixture struct {
	failure                error
	checks, links, unlinks int
	user                   accountdomain.UserID
	hash, issuer           string
	key                    accountdomain.IdentityKey
}

func (f *managementFixture) RequireFresh(_ context.Context, user accountdomain.UserID, hash string) error {
	f.checks++
	f.user, f.hash = user, hash
	return f.failure
}

func (f *managementFixture) Link(_ context.Context, user accountdomain.UserID, hash string, key accountdomain.IdentityKey) error {
	f.links++
	f.user, f.hash, f.key = user, hash, key
	return f.failure
}

func (f *managementFixture) Unlink(_ context.Context, user accountdomain.UserID, hash, issuer string) error {
	f.unlinks++
	f.user, f.hash, f.issuer = user, hash, issuer
	return f.failure
}

func TestLinkFlow(t *testing.T) {
	for _, failure := range []string{"", "missing session", "other session", "expired proof", "occupied identity", "provider"} {
		t.Run(failure, func(t *testing.T) {
			login, management := &loginFixture{}, &managementFixture{}
			tokens := tokengenerate.New()
			s := New(Config{Enabled: true, IPLimit: 30, GlobalLimit: 1000}, login, login, login, login, tokens, management)
			user := accountdomain.UserID("12345678-1234-1234-1234-123456789abc")
			session, err := tokens.GenerateToken()
			if err != nil {
				t.Fatal(err)
			}
			hash := tokens.Hash(session)
			started, err := s.StartLink(t.Context(), user, hash, "ip")
			if err != nil || started == nil || login.flow.Purpose != domain.Link || login.flow.UserID != user || login.flow.SessionHash != hash || management.checks != 1 {
				t.Fatal(started, err)
			}
			input := CallbackInput{Code: "code", State: login.state, Binding: login.binding, SessionToken: session, IP: "ip"}
			switch failure {
			case "missing session":
				input.SessionToken = ""
			case "other session":
				input.SessionToken = strings.Repeat("A", 43)
			case "expired proof":
				management.failure = accountdomain.ErrFreshAuthRequired
			case "occupied identity":
				management.failure = accountdomain.ErrIdentityConflict
			case "provider":
				login.failure = "proof"
			}
			result, err := s.Callback(t.Context(), input)
			if failure == "" {
				if err != nil || !result.Linked || result.Session != nil || management.links != 1 || management.user != user || management.hash != hash || management.key.Issuer != domain.Issuer {
					t.Fatal(result, err, management)
				}
			} else if err == nil || result != nil {
				t.Fatal("failed link succeeded", result, err)
			}
			if login.resolutions != 0 || login.sessions != 0 {
				t.Fatal("link silently became login/registration")
			}
			if failure == "missing session" || failure == "other session" {
				if login.proofs != 0 || management.links != 0 {
					t.Fatal("wrong session reached provider/database")
				}
			}
			if _, err := s.Callback(t.Context(), input); !errors.Is(err, domain.ErrInvalidFlow) {
				t.Fatal("link replay", err)
			}
		})
	}
}

func TestLinkStartAndUnlinkGates(t *testing.T) {
	login, management := &loginFixture{}, &managementFixture{failure: accountdomain.ErrFreshAuthRequired}
	s := New(Config{Enabled: true, IPLimit: 30, GlobalLimit: 1000}, login, login, login, login, tokengenerate.New(), management)
	if started, err := s.StartLink(t.Context(), "user", "hash", "ip"); !errors.Is(err, accountdomain.ErrFreshAuthRequired) || started != nil || login.state != "" {
		t.Fatal("flow saved without fresh proof", started, err)
	}
	management.failure = nil
	if err := s.Unlink(t.Context(), "user", "hash", "ip"); err != nil || management.unlinks != 1 || management.issuer != domain.Issuer {
		t.Fatal(err, management)
	}
	login.failure = "limit"
	if err := s.Unlink(t.Context(), "user", "hash", "ip"); !errors.Is(err, domain.ErrLimited) || management.unlinks != 1 {
		t.Fatal("unlink skipped budgets", err)
	}
	disabled := New(Config{}, nil, nil, nil, nil, nil, nil)
	if _, err := disabled.StartLink(t.Context(), "user", "hash", "ip"); !errors.Is(err, domain.ErrDisabled) {
		t.Fatal(err)
	}
	if err := disabled.Unlink(t.Context(), "user", "hash", "ip"); !errors.Is(err, domain.ErrDisabled) {
		t.Fatal(err)
	}
}

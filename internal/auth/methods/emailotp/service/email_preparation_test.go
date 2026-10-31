package service

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type preparationFixture struct {
	challenge   domain.Challenge
	calls       int
	email       string
	deadline    time.Time
	replacement string
}

func (f *preparationFixture) IssueEmailPreparation(_ context.Context, _ mfaservice.Proof, email string, c domain.Challenge) (time.Time, error) {
	f.calls++
	f.challenge = c
	f.email = email
	return f.deadline, nil
}

func (f *preparationFixture) ConfirmEmailPreparation(_ context.Context, _ mfaservice.Proof, digest, verifier, replacement string) (*ReauthenticatedSession, error) {
	f.calls++
	if digest != f.challenge.Digest || verifier != f.challenge.Verifier {
		return nil, domain.ErrInvalidPreparation
	}
	f.replacement = replacement
	return &ReauthenticatedSession{VerifiedAt: time.Now(), ExpiresAt: f.deadline}, nil
}

func TestEmailPreparationPurposeAndAdmission(t *testing.T) {
	_, limits, cipher := otpFixture(t)
	f := &preparationFixture{deadline: time.Now().Add(30 * time.Second)}
	tokens := tokengenerate.New()
	s, err := NewEmailPreparation(f, cipher, limits, tokens, EmailPreparationConfig{TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestsPerMinute: 100, ConfirmationsPerMinute: 1000})
	if err != nil {
		t.Fatal(err)
	}
	proof := mfaservice.Proof{UserID: "00000000-0000-4000-8000-000000000001", TokenHash: strings.Repeat("a", 64), AuthVersion: 1}
	requested, err := s.Request(t.Context(), proof, "User@Example.test", "192.0.2.1")
	if err != nil || requested.ExpiresAt != f.deadline || f.email != "user@example.test" {
		t.Fatal("preparation request", err)
	}
	plain, err := cipher.Open(f.challenge.Payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	var message codeMail
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`<strong>([0-9]{8})</strong>`).FindStringSubmatch(message.Body)
	if len(match) != 2 || message.To != f.email {
		t.Fatal("invalid preparation mail")
	}
	if f.challenge.Digest == cipher.Digest("binding:"+requested.Binding) || f.challenge.Digest == cipher.Digest("reauth:binding:"+requested.Binding) {
		t.Fatal("purposes share a digest")
	}
	result, err := s.Confirm(t.Context(), EmailPreparationConfirmation{Proof: proof, Binding: requested.Binding, Code: match[1], IP: "192.0.2.1"})
	if err != nil || result.Token == "" || tokens.Hash(result.Token) != f.replacement {
		t.Fatal("rotation secret not bound", err)
	}
	for _, failure := range []error{nil, errors.New("Redis unavailable")} {
		limits.allowed = false
		limits.fail = failure
		calls := f.calls
		if result, err := s.Request(t.Context(), proof, f.email, "192.0.2.1"); result != nil || err == nil || f.calls != calls {
			t.Fatal("failed admission reached SQL")
		}
	}
	other, err := secretbox.NewScoped("bG9jYWwtb25seS1hdXRoLW91dGJveC1rZXktMzJieXQ=", "foreign-email-scope")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(f.challenge.Payload); err == nil {
		t.Fatal("foreign scope opened payload")
	}
}

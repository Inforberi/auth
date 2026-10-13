package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

type loginFixture struct {
	challenge       domain.Challenge
	email           string
	consumed        int
	issued          int
	allowed         bool
	fail            error
	sessionFail     error
	sessionCalls    int
	keys            []string
	expectedVersion int64
	primary         mfaservice.PrimaryProof
}

func (f *loginFixture) Issue(_ context.Context, email string, c domain.Challenge) error {
	f.issued++
	f.email = email
	f.challenge = c
	return f.fail
}

func (f *loginFixture) Consume(_ context.Context, digest, verifier string) (*AuthenticatedAccount, error) {
	f.consumed++
	if f.fail != nil {
		return nil, f.fail
	}
	if f.challenge.Digest != digest || f.challenge.Verifier != verifier {
		return nil, domain.ErrInvalidCode
	}
	return &AuthenticatedAccount{User: accountdomain.User{ID: "00000000-0000-0000-0000-000000000001", AuthVersion: 7}, EmailID: "00000000-0000-0000-0000-000000000002"}, nil
}

func (f *loginFixture) BeginLogin(ctx context.Context, proof mfaservice.PrimaryProof, agent, ip string) (*sessionservice.CreatedSession, error) {
	f.primary = proof
	return f.CreateSessionAtVersion(ctx, proof.UserID, agent, ip, proof.AuthVersion)
}

func (f *loginFixture) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	f.keys = append(f.keys, key)
	return f.allowed, f.fail
}

func (f *loginFixture) CreateSessionAtVersion(_ context.Context, _ accountdomain.UserID, _, _ string, v int64) (*sessionservice.CreatedSession, error) {
	f.sessionCalls++
	f.expectedVersion = v
	if f.sessionFail != nil {
		return nil, f.sessionFail
	}
	return &sessionservice.CreatedSession{RawToken: "session-secret", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func otpFixture(t *testing.T) (*Service, *loginFixture, *secretbox.Cipher) {
	t.Helper()
	c, err := secretbox.NewScoped("bG9jYWwtb25seS1hdXRoLW91dGJveC1rZXktMzJieXQ=", "email-login:v1")
	if err != nil {
		t.Fatal(err)
	}
	f := &loginFixture{allowed: true}
	cfg := Config{Enabled: true, TTL: 5 * time.Minute, ResendInterval: time.Minute, RequestGlobalLimit: 1000, ConfirmGlobalLimit: 1000}
	return New(f, c, f, f, tokengenerate.New(), cfg), f, c
}

func TestRequestAndConfirm(t *testing.T) {
	s, f, c := otpFixture(t)
	got, err := s.Request(context.Background(), " User@Example.test ", "192.0.2.1")
	if err != nil || !domain.ValidBinding(got.Binding) || f.email != "user@example.test" || len(f.keys) != 4 {
		t.Fatal(got, err, f)
	}
	plain, err := c.Open(f.challenge.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var mail loginMail
	if err = json.Unmarshal(plain, &mail); err != nil || mail.To != f.email {
		t.Fatal(err)
	}
	start := strings.Index(mail.Body, "<strong>") + len("<strong>")
	code := mail.Body[start : start+8]
	if !domain.ValidCode(code) || f.challenge.Verifier != c.Digest("code:"+got.Binding+":"+code) {
		t.Fatal("incorrect code verifier")
	}
	if strings.Contains(string(f.challenge.Payload), code) {
		t.Fatal("plaintext code in SQL payload")
	}
	for _, key := range f.keys {
		if strings.Contains(key, "example.test") || strings.Contains(key, "192.0.2.1") {
			t.Fatal("PII in limiter key")
		}
	}
	result, err := s.Confirm(context.Background(), ConfirmInput{Binding: got.Binding, Code: code, IP: "192.0.2.1"})
	if err != nil || result.RawToken != "session-secret" || f.sessionCalls != 1 || f.expectedVersion != 7 {
		t.Fatal(result, err, f)
	}
	if f.primary.Method != "emailotp" || f.primary.Reference != "00000000-0000-0000-0000-000000000002" || f.primary.VerifiedAt.IsZero() {
		t.Fatal("consumed email proof lost", f.primary)
	}
}

func TestInputAndDisabledBeforeDependencies(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s, f, _ := otpFixture(t)
		s.cfg.Enabled = enabled
		if _, err := s.Request(context.Background(), "bad", "ip"); err == nil {
			t.Fatal("accepted invalid/disabled request")
		}
		if _, err := s.Confirm(context.Background(), ConfirmInput{Binding: "invalid", Code: "12"}); err == nil {
			t.Fatal("accepted invalid/disabled confirm")
		}
		if len(f.keys) != 0 || f.issued != 0 || f.consumed != 0 || f.sessionCalls != 0 {
			t.Fatal("dependencies before validation")
		}
	}
	for _, code := range []string{"", "1234567", "123456789", "1234abcd", "１２３４５６７８"} {
		s, f, _ := otpFixture(t)
		if _, err := s.Confirm(context.Background(), ConfirmInput{Binding: strings.Repeat("A", 43), Code: code}); !errors.Is(err, domain.ErrInvalidCode) || len(f.keys) != 0 {
			t.Fatal(code, err)
		}
	}
}

func TestLimitsAndDependencyFailure(t *testing.T) {
	for _, fail := range []error{nil, errors.New("redis unavailable")} {
		s, f, _ := otpFixture(t)
		f.allowed = false
		f.fail = fail
		_, err := s.Request(context.Background(), "user@example.test", "ip")
		if err == nil || f.issued != 0 {
			t.Fatal("request bypass")
		}
		_, err = s.Confirm(context.Background(), ConfirmInput{Binding: strings.Repeat("A", 43), Code: "12345678"})
		if err == nil || f.consumed != 0 || f.sessionCalls != 0 {
			t.Fatal("confirm bypass")
		}
	}
	s, f, c := otpFixture(t)
	f.challenge = domain.Challenge{Digest: c.Digest("binding:" + strings.Repeat("A", 43)), Verifier: "wrong"}
	_, err := s.Confirm(context.Background(), ConfirmInput{Binding: strings.Repeat("A", 43), Code: "12345678"})
	if !errors.Is(err, domain.ErrInvalidCode) || f.sessionCalls != 0 {
		t.Fatal("bad code created session", err)
	}
	f.challenge.Verifier = c.Digest("code:" + strings.Repeat("A", 43) + ":12345678")
	f.sessionFail = errors.New("session unavailable")
	_, err = s.Confirm(context.Background(), ConfirmInput{Binding: strings.Repeat("A", 43), Code: "12345678"})
	if !errors.Is(err, f.sessionFail) || f.sessionCalls != 1 {
		t.Fatal("session failure hidden", err)
	}
}

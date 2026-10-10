package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type repository struct {
	issued    domain.Verification
	confirmed string
	job       *domain.VerificationDelivery
	finished  bool
	sent      bool
}

func (r *repository) Issue(_ context.Context, _ string, v domain.Verification, _ time.Duration) error {
	r.issued = v
	return nil
}

func (r *repository) Confirm(_ context.Context, digest string) error {
	r.confirmed = digest
	return nil
}

func (*repository) RequireVerified(context.Context, domain.UserID) error { return nil }

func (r *repository) ClaimDelivery(context.Context) (*domain.VerificationDelivery, error) {
	return r.job, nil
}

func (r *repository) FinishDelivery(_ context.Context, _ domain.VerificationDelivery, sent bool) error {
	r.finished = true
	r.sent = sent
	return nil
}

type limiter struct {
	allowed bool
	err     error
	keys    []string
}

func (l *limiter) Allow(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
	l.keys = append(l.keys, key)
	return l.allowed, l.err
}

type mailer struct {
	err  error
	to   string
	body string
}

func (m *mailer) SendContext(_ context.Context, to, _, body string) error {
	m.to = to
	m.body = body
	return m.err
}

func fixture(t *testing.T) (*service.Service, *repository, *limiter, *mailer, *secretbox.Cipher) {
	t.Helper()
	c, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	r := &repository{}
	l := &limiter{allowed: true}
	m := &mailer{}
	s := service.New(r, l, c, m, service.Config{URL: "https://example.com/verify", TTL: 30 * time.Minute, ResendInterval: time.Minute})
	return s, r, l, m, c
}

func TestVerificationPreparationAndDelivery(t *testing.T) {
	s, r, _, m, c := fixture(t)
	if err := s.Resend(context.Background(), "USER@example.com", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	plain, err := c.Open(r.issued.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var message struct {
		To   string
		Link string
	}
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(message.Link)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("token")
	if len(token) != 43 || len(r.issued.Digest) != 64 || message.To != "user@example.com" {
		t.Fatal("invalid challenge")
	}
	if err := s.Confirm(context.Background(), token, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if r.confirmed != r.issued.Digest {
		t.Fatal("verifier mismatch")
	}
	r.job = &domain.VerificationDelivery{Payload: r.issued.Payload}
	if err := s.DeliverOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !r.finished || !r.sent || m.to != message.To || m.body == "" {
		t.Fatal("delivery failed")
	}
	m.err = errors.New("SMTP unavailable")
	r.finished = false
	if err := s.DeliverOne(context.Background()); err == nil || !r.finished || r.sent {
		t.Fatal("failed delivery not rescheduled")
	}
}

func TestVerificationLimitsAndTokens(t *testing.T) {
	s, r, l, _, _ := fixture(t)
	for _, token := range []string{"", "short", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"} {
		if !errors.Is(s.Confirm(context.Background(), token, "ip"), domain.ErrInvalidVerification) {
			t.Fatal("malformed token accepted")
		}
	}
	if r.confirmed != "" {
		t.Fatal("malformed token reached repository")
	}
	l.allowed = false
	if !errors.Is(s.Resend(context.Background(), "user@example.com", "ip"), domain.ErrVerificationLimited) {
		t.Fatal("limit bypassed")
	}
	l.err = errors.New("Redis down")
	if err := s.AllowRegistration(context.Background(), "ip"); !errors.Is(err, l.err) {
		t.Fatal("limiter failed open")
	}
}

func TestResendValidatesBeforeDependencies(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  error
	}{
		{"", domain.ErrEmailRequired},
		{"   ", domain.ErrEmailRequired},
		{"bad", domain.ErrEmailInvalid},
	} {
		t.Run(tc.input, func(t *testing.T) {
			s, repo, limiter, _, _ := fixture(t)
			limiter.allowed = false
			limiter.err = errors.New("Redis down")
			if err := s.Resend(context.Background(), tc.input, "ip"); !errors.Is(err, tc.want) {
				t.Fatal("email error precedence changed", err)
			}
			if len(limiter.keys) != 0 || repo.issued.Digest != "" {
				t.Fatal("invalid email reached dependencies")
			}
		})
	}
}

func TestVerificationConfig(t *testing.T) {
	cfg := service.Config{URL: "https://example.com/verify", EncryptionKey: "bG9jYWwtb25seS1hdXRoLW91dGJveC1rZXktMzJieXQ=", TTL: 30 * time.Minute, ResendInterval: time.Minute, RegistrationIPLimit: 5, RegistrationGlobalLimit: 100}
	if err := cfg.Validate(false); err != nil {
		t.Fatal(err)
	}
	if cfg.Validate(true) == nil {
		t.Fatal("sample production key accepted")
	}
	for _, u := range []string{"https://user:secret@example.com/verify", "https://example.com/verify?redirect=evil", "https://example.com/verify#token"} {
		cfg.URL = u
		if cfg.Validate(false) == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}

func TestConfirmBoundsBeforeLimits(t *testing.T) {
	for _, size := range []int{0, 43, 128, 129, 1024} {
		s, repo, limiter, _, _ := fixture(t)
		limiter.allowed = false
		want := domain.ErrVerificationLimited
		if size > 128 {
			want = domain.ErrInvalidVerification
		}
		if err := s.Confirm(context.Background(), strings.Repeat("A", size), "ip"); !errors.Is(err, want) {
			t.Fatal(size, err)
		}
		if (size > 128 && len(limiter.keys) != 0) || repo.confirmed != "" {
			t.Fatal("oversized token reached dependencies or limited token reached SQL")
		}
	}
}

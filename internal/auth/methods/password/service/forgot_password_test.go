package service

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type recoveryRepo struct {
	challenge domain.ResetChallenge
	consumed  string
	hash      string
	err       error
	job       *domain.ResetDelivery
	sent      bool
}

func (r *recoveryRepo) IssueReset(_ context.Context, _ string, c domain.ResetChallenge) error {
	r.challenge = c
	return r.err
}

func (r *recoveryRepo) ConsumeReset(_ context.Context, digest, hash string) error {
	r.consumed = digest
	r.hash = hash
	return r.err
}

func (r *recoveryRepo) ClaimResetDelivery(context.Context) (*domain.ResetDelivery, error) {
	return r.job, r.err
}

func (r *recoveryRepo) FinishResetDelivery(_ context.Context, _ domain.ResetDelivery, sent bool) error {
	r.sent = sent
	return nil
}

type recoveryLimit struct {
	allow bool
	err   error
}

func (l *recoveryLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	return l.allow, l.err
}

type recoveryMail struct {
	to  string
	err error
}

func (m *recoveryMail) SendContext(_ context.Context, to, _, _ string) error { m.to = to; return m.err }

type recoveryHash struct{}

func (recoveryHash) GenerateHash([]byte) (string, error) { return "new-hash", nil }
func (recoveryHash) Compare(string, string) error        { return nil }

func TestRecovery(t *testing.T) {
	cipher, err := secretbox.NewScoped("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "password-reset:v1")
	if err != nil {
		t.Fatal(err)
	}
	repo := &recoveryRepo{}
	limits := &recoveryLimit{allow: true}
	mail := &recoveryMail{}
	service := NewRecovery(repo, cipher, limits, mail, recoveryHash{}, Config{ResetURL: "https://example.com/reset", ResetTokenTTL: time.Hour})
	if err := service.Forgot(context.Background(), "USER@example.com", "ip"); err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Open(repo.challenge.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var message resetMail
	if err := json.Unmarshal(plain, &message); err != nil {
		t.Fatal(err)
	}
	token := regexp.MustCompile(`token=([A-Za-z0-9_-]+)`).FindStringSubmatch(message.Body)
	if len(token) != 2 || len(token[1]) != 43 || message.To != "user@example.com" {
		t.Fatal("invalid reset email")
	}
	if err := service.Reset(context.Background(), token[1], "ExamplePass2", "ExamplePass2", "ip"); err != nil {
		t.Fatal(err)
	}
	if repo.consumed != repo.challenge.Digest || repo.hash != "new-hash" {
		t.Fatal("incorrect reset consume")
	}
	for _, tc := range []struct {
		token, password, confirm string
		expected                 error
	}{
		{"bad", "ExamplePass2", "ExamplePass2", domain.ErrInvalidReset},
		{token[1], "weak", "weak", domain.ErrPasswordTooShort},
		{token[1], "ExamplePass2", "ExamplePass3", domain.ErrPasswordConfirmation},
	} {
		repo.consumed = ""
		if err := service.Reset(context.Background(), tc.token, tc.password, tc.confirm, "ip"); !errors.Is(err, tc.expected) || repo.consumed != "" {
			t.Fatal("invalid request consumed token", err)
		}
	}
	repo.job = &domain.ResetDelivery{Payload: repo.challenge.Payload}
	if _, err := service.DeliverOne(context.Background()); err != nil || !repo.sent || mail.to != "user@example.com" {
		t.Fatal("delivery failed", err)
	}
	mail.err = errors.New("SMTP down")
	if _, err := service.DeliverOne(context.Background()); !errors.Is(err, mail.err) || repo.sent {
		t.Fatal("SMTP failure lost", err)
	}
	limits.allow = false
	if err := service.Forgot(context.Background(), "user@example.com", "ip"); !errors.Is(err, domain.ErrRecoveryLimited) {
		t.Fatal("limiter bypass")
	}
	limits.err = errors.New("Redis unavailable")
	if err := service.Forgot(context.Background(), "user@example.com", "ip"); !errors.Is(err, limits.err) {
		t.Fatal("limiter failed open")
	}
}

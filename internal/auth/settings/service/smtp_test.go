package service

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/secretbox"
)

type smtpRepo struct {
	SMTPRepository
	stored SMTPStored
	input  SMTPUpdate
	err    error
	calls  int
}

func (r *smtpRepo) LoadSMTP(context.Context) (SMTPStored, error) { return r.stored, r.err }
func (r *smtpRepo) AuthorizeSMTPTest(context.Context, accessservice.Principal, int64) (SMTPStored, error) {
	r.calls++
	return r.stored, r.err
}

func (r *smtpRepo) UpdateSMTP(_ context.Context, input SMTPUpdate) (domain.SMTPSnapshot, error) {
	r.calls++
	r.input = input
	return r.stored.SMTPSnapshot, r.err
}

type smtpLimit struct {
	allowed bool
	err     error
	calls   int
}

func (l *smtpLimit) Allow(context.Context, string, int, time.Duration) (bool, error) {
	l.calls++
	return l.allowed, l.err
}

func smtpServiceFixture(t *testing.T) (*SMTP, *smtpRepo, *smtpLimit) {
	t.Helper()
	cipher, err := secretbox.NewScoped(base64.StdEncoding.EncodeToString(make([]byte, 32)), "smtp-settings:v1")
	if err != nil {
		t.Fatal(err)
	}
	password, err := cipher.Seal([]byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	r := &smtpRepo{stored: SMTPStored{SMTPSnapshot: domain.SMTPSnapshot{
		Version: 1,
		Config:  domain.SMTPConfig{Host: "smtp.example.com", Port: 587, From: "auth@example.com", Domain: "example.com", RequireTLS: true}, PasswordSet: true,
	}, Password: password}}
	limits := &smtpLimit{allowed: true}
	s, err := NewSMTP(r, cipher, func(context.Context, domain.SMTPConfig, string) error { return nil }, limits, []string{"smtp.example.com:587"}, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, limits
}

var smtpActor = accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}

func TestSMTPAdmissionAndSecrets(t *testing.T) {
	s, repo, _ := smtpServiceFixture(t)
	secret := "new-synthetic-secret"
	input := SMTPUpdateInput{Actor: smtpActor, ExpectedVersion: 1, Config: repo.stored.Config, Password: &secret}
	if _, err := s.Update(t.Context(), input); err != nil || repo.calls != 1 || string(repo.input.Password) == secret || !repo.input.PasswordSet {
		t.Fatal("secret was not encrypted before storage", err)
	}
	for _, change := range []func(*SMTPUpdateInput){
		func(i *SMTPUpdateInput) { i.Actor = accessservice.Principal{} },
		func(i *SMTPUpdateInput) { i.ExpectedVersion = 0 },
		func(i *SMTPUpdateInput) { i.Config.Host = "169.254.169.254" },
		func(i *SMTPUpdateInput) { i.Config.RequireTLS = false },
	} {
		bad := input
		change(&bad)
		if _, err := s.Update(t.Context(), bad); err == nil || repo.calls != 1 {
			t.Fatal("invalid update reached storage", err)
		}
	}
	config, password, err := s.Credentials(t.Context())
	if err != nil || config != repo.stored.Config || password != "synthetic-password" {
		t.Fatal("delivery did not load saved credentials", err)
	}
	repo.stored.Password[0] ^= 1
	if _, _, err := s.Credentials(t.Context()); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
}

func TestSMTPTestAdmissionAndSanitization(t *testing.T) {
	s, repo, limits := smtpServiceFixture(t)
	called := 0
	s.probe = func(context.Context, domain.SMTPConfig, string) error {
		called++
		return errors.New("private hostname/password")
	}
	if err := s.TestConnection(t.Context(), smtpActor, 1); !errors.Is(err, ErrSMTPTestFailed) || strings.Contains(err.Error(), "private") || called != 1 || limits.calls != 2 {
		t.Fatal("probe error leaked", err)
	}
	repo.err = accessdomain.ErrForbidden
	if err := s.TestConnection(t.Context(), smtpActor, 1); !errors.Is(err, accessdomain.ErrForbidden) || called != 1 {
		t.Fatal(err)
	}
	repo.err = nil
	limits.allowed = false
	if err := s.TestConnection(t.Context(), smtpActor, 1); !errors.Is(err, ErrSMTPTestLimited) || called != 1 {
		t.Fatal(err)
	}
	limits.err = errors.New("redis password")
	if err := s.TestConnection(t.Context(), smtpActor, 1); err == nil || strings.Contains(err.Error(), "password") || called != 1 {
		t.Fatal(err)
	}
	s.tests <- struct{}{}
	s.tests <- struct{}{}
	if err := s.TestConnection(t.Context(), smtpActor, 1); !errors.Is(err, ErrSMTPTestLimited) {
		t.Fatal("concurrency unbounded", err)
	}
}

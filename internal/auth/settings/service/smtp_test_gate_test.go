package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func TestSMTPTestGateSurvivesServiceReplacement(t *testing.T) {
	gate := NewSMTPTestGate()
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	newService := func() *SMTP {
		t.Helper()
		fixture, repo, limits := smtpServiceFixture(t)
		s, err := NewSMTPWithTestGate(repo, fixture.cipher, func(ctx context.Context, _ domain.SMTPConfig, _ string) error {
			entered <- struct{}{}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, limits, []string{"smtp.example.com:587"}, true, gate)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	first, second, replacement := newService(), newService(), newService()
	done := make(chan error, 2)
	go func() { done <- first.TestConnection(ctx, smtpActor, 1) }()
	go func() { done <- second.TestConnection(ctx, smtpActor, 1) }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("SMTP tests did not enter the probe")
		}
	}
	if err := replacement.TestConnection(ctx, smtpActor, 1); !errors.Is(err, ErrSMTPTestLimited) {
		t.Fatalf("replacement bypassed the shared test gate: %v", err)
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := replacement.TestConnection(ctx, smtpActor, 1); err != nil {
		t.Fatal(err)
	}
}

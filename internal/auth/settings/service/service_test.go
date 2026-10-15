package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type settingsRepository struct {
	stored                             domain.Snapshot
	loadErr, errorResult               error
	loads, initializes, reads, updates int
	input                              UpdateInput
}

func settingsDeadline(ctx context.Context) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 3*time.Second {
		panic("unbounded settings operation")
	}
}

func (r *settingsRepository) Load(ctx context.Context) (domain.Snapshot, error) {
	settingsDeadline(ctx)
	r.loads++
	return r.stored, r.loadErr
}

func (r *settingsRepository) Initialize(ctx context.Context, p domain.Policy) (domain.Snapshot, error) {
	settingsDeadline(ctx)
	r.initializes++
	return domain.Snapshot{Version: 1, Policy: p}, r.errorResult
}

func (r *settingsRepository) Read(ctx context.Context, _ accessservice.Principal) (domain.Snapshot, error) {
	settingsDeadline(ctx)
	r.reads++
	return r.stored, r.errorResult
}

func (r *settingsRepository) Update(ctx context.Context, input UpdateInput) (domain.Snapshot, error) {
	settingsDeadline(ctx)
	r.updates++
	r.input = input
	return r.stored, r.errorResult
}

func TestSettingsInitialization(t *testing.T) {
	p := domain.Policy{Methods: domain.PublicMethods{Password: true}, PasswordEmailVerification: domain.VerificationOptional}
	r := &settingsRepository{loadErr: domain.ErrNotInitialized}
	s := New(r)
	if got, err := s.Initialize(context.Background(), p); err != nil || got.Policy != p || got.Version != 1 || r.initializes != 1 {
		t.Fatal(got, err)
	}
	r.loadErr = nil
	r.stored = domain.Snapshot{Version: 9, Policy: p}
	if got, err := s.Initialize(context.Background(), domain.Policy{}); err != nil || got != r.stored || r.initializes != 1 {
		t.Fatal("bootstrap replaced persisted source", got, err)
	}
	r.loadErr = errors.New("database unavailable")
	if _, err := s.Initialize(context.Background(), p); !errors.Is(err, r.loadErr) || r.initializes != 1 {
		t.Fatal("dependency failure treated as first install", err)
	}
	r.loadErr = domain.ErrNotInitialized
	if _, err := s.Initialize(context.Background(), domain.Policy{}); !errors.Is(err, domain.ErrInvalidPolicy) || r.initializes != 1 {
		t.Fatal("invalid seed stored", err)
	}
}

func TestSettingsReadUpdate(t *testing.T) {
	actor := accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	r := &settingsRepository{}
	s := New(r)
	if _, err := s.Read(context.Background(), accessservice.Principal{}); !errors.Is(err, accessdomain.ErrForbidden) || r.reads != 0 {
		t.Fatal(err)
	}
	input := UpdateInput{Actor: actor, ExpectedVersion: 1, Policy: domain.Policy{PasswordEmailVerification: domain.VerificationRequired}}
	for _, mutate := range []func(*UpdateInput){func(i *UpdateInput) { i.Actor.TokenHash = "bad" }, func(i *UpdateInput) { i.ExpectedVersion = 0 }, func(i *UpdateInput) { i.Policy.PasswordEmailVerification = "" }} {
		bad := input
		mutate(&bad)
		if _, err := s.Update(context.Background(), bad); err == nil || r.updates != 0 {
			t.Fatal("invalid input reached SQL", err)
		}
	}
	if _, err := s.Read(context.Background(), actor); err != nil || r.reads != 1 {
		t.Fatal(err)
	}
	if _, err := s.Update(context.Background(), input); err != nil || r.updates != 1 || r.input != input {
		t.Fatal(err)
	}
	for _, failure := range []error{domain.ErrPolicyConflict, accessdomain.ErrFreshAuthRequired, errors.New("SQL failure")} {
		r.errorResult = failure
		if _, err := s.Update(context.Background(), input); !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
}

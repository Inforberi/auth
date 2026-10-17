package service

import (
	"context"
	"errors"
	"testing"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type retentionRepoStub struct {
	RetentionRepository
	stored                          domain.RetentionSnapshot
	input                           RetentionUpdateInput
	loads, initializations, updates int
	err                             error
}

func (r *retentionRepoStub) LoadRetention(context.Context) (domain.RetentionSnapshot, error) {
	r.loads++
	return r.stored, r.err
}

func (r *retentionRepoStub) InitializeRetention(_ context.Context, p domain.RetentionPolicy) (domain.RetentionSnapshot, error) {
	r.initializations++
	r.stored = domain.RetentionSnapshot{Version: 1, Policy: p}
	return r.stored, nil
}

func (r *retentionRepoStub) UpdateRetention(_ context.Context, input RetentionUpdateInput) (domain.RetentionSnapshot, error) {
	r.updates++
	r.input = input
	return r.stored, r.err
}

func TestRetentionSettings(t *testing.T) {
	p := domain.RetentionPolicy{EmailReservationDays: 30, SessionDays: 30, SecurityAuditDays: 180}
	r := &retentionRepoStub{err: domain.ErrNotInitialized}
	s := NewRetention(r)
	if err := s.Initialize(t.Context(), p); err != nil || r.initializations != 1 {
		t.Fatal(err)
	}
	r.err = nil
	if err := s.Initialize(t.Context(), domain.RetentionPolicy{}); err != nil || r.initializations != 1 {
		t.Fatal("saved settings overwritten by ENV", err)
	}
	if got, err := s.Current(t.Context()); err != nil || got != p {
		t.Fatal(got, err)
	}
	r.stored.Policy.SessionDays = 90
	if got, err := s.Current(t.Context()); err != nil || got.SessionDays != 90 {
		t.Fatal("stale snapshot", got, err)
	}
	r.err = errors.New("unavailable")
	if _, err := s.Current(t.Context()); !errors.Is(err, r.err) {
		t.Fatal("fallback after dependency failure", err)
	}
	r.err = nil
	r.stored.Policy.SessionDays = 0
	if _, err := s.Current(t.Context()); !errors.Is(err, domain.ErrInvalidRetention) {
		t.Fatal("corrupt snapshot", err)
	}
	input := RetentionUpdateInput{Actor: smtpActor, ExpectedVersion: 1, Policy: p, ConfirmShortening: true}
	if _, err := s.Update(t.Context(), input); err != nil || r.input != input {
		t.Fatal("update contract", err)
	}
	input.Policy.SessionDays = 0
	if _, err := s.Update(t.Context(), input); !errors.Is(err, domain.ErrInvalidRetention) || r.updates != 1 {
		t.Fatal("invalid policy reached SQL", err)
	}
	input.Actor.TokenHash = ""
	if _, err := s.Update(t.Context(), input); !errors.Is(err, accessdomain.ErrForbidden) {
		t.Fatal("untrusted actor", err)
	}
}

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type statusRepoStub struct {
	calls  int
	err    error
	change domain.StatusChange
}

func (r *statusRepoStub) ChangeStatus(ctx context.Context, change domain.StatusChange) (domain.AuthVersion, error) {
	r.calls++
	r.change = change
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		panic("status operation must be bounded")
	}
	if r.err != nil {
		return 0, r.err
	}
	return change.ExpectedVersion + 1, nil
}

func TestStatusChangeValidation(t *testing.T) {
	valid := domain.StatusChange{UserID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222", ExpectedVersion: 1, Status: domain.StatusBlocked}
	for name, mutate := range map[string]func(*domain.StatusChange){
		"status":  func(c *domain.StatusChange) { c.Status = "paid" },
		"version": func(c *domain.StatusChange) { c.ExpectedVersion = 0 },
		"user":    func(c *domain.StatusChange) { c.UserID = "invalid" },
		"actor":   func(c *domain.StatusChange) { c.ActorID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			change := valid
			mutate(&change)
			repo := &statusRepoStub{}
			version, err := NewStatus(repo).Change(context.Background(), change)
			if !errors.Is(err, domain.ErrInvalidStatusChange) || version != 0 || repo.calls != 0 {
				t.Fatal("invalid input reached storage", err)
			}
		})
	}
	repo := &statusRepoStub{}
	version, err := NewStatus(repo).Change(context.Background(), valid)
	if err != nil || version != 2 || repo.change != valid {
		t.Fatal("status contract lost", err)
	}
	for _, failure := range []error{domain.ErrAccountNotFound, domain.ErrAccountConflict, domain.ErrAccountDeleted, errors.New("database unavailable")} {
		repo.err = failure
		version, err := NewStatus(repo).Change(context.Background(), valid)
		if version != 0 || !errors.Is(err, failure) {
			t.Fatal("repository error changed", err)
		}
	}
}

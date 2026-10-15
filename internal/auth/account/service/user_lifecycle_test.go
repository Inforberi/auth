package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type lifecycleRepository struct {
	calls    int
	actor    accessservice.Principal
	change   domain.StatusChange
	deletion domain.AccountDeletion
	err      error
}

func (r *lifecycleRepository) ChangeUserStatus(ctx context.Context, actor accessservice.Principal, change domain.StatusChange) (domain.AuthVersion, error) {
	r.change = change
	return r.record(ctx, actor)
}

func (r *lifecycleRepository) DeleteUserAccount(ctx context.Context, actor accessservice.Principal, deletion domain.AccountDeletion) (domain.AuthVersion, error) {
	r.deletion = deletion
	return r.record(ctx, actor)
}

func (r *lifecycleRepository) record(ctx context.Context, actor accessservice.Principal) (domain.AuthVersion, error) {
	r.calls++
	r.actor = actor
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
		panic("unbounded lifecycle operation")
	}
	if r.err != nil {
		return 0, r.err
	}
	return 2, nil
}

func TestUserLifecycle(t *testing.T) {
	actor := accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	target := domain.UserID("22222222-2222-4222-8222-222222222222")
	for _, action := range []string{"status", "delete"} {
		t.Run(action, func(t *testing.T) {
			repo := &lifecycleRepository{}
			s := NewUserLifecycle(repo)
			invoke := func(principal accessservice.Principal, id domain.UserID, version domain.AuthVersion, status domain.Status) (domain.AuthVersion, error) {
				if action == "status" {
					return s.ChangeStatus(context.Background(), principal, domain.StatusChange{UserID: id, ActorID: target, ExpectedVersion: version, Status: status})
				}
				return s.Delete(context.Background(), principal, domain.AccountDeletion{UserID: id, ActorID: target, ExpectedVersion: version})
			}
			if _, err := invoke(accessservice.Principal{}, target, 1, domain.StatusBlocked); !errors.Is(err, accessdomain.ErrForbidden) {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				id      domain.UserID
				version domain.AuthVersion
			}{{"invalid", 1}, {target, 0}} {
				if _, err := invoke(actor, tc.id, tc.version, domain.StatusBlocked); err == nil {
					t.Fatal("invalid command accepted")
				}
			}
			if action == "status" {
				if _, err := invoke(actor, target, 1, "pending"); !errors.Is(err, domain.ErrInvalidStatusChange) {
					t.Fatal(err)
				}
			}
			if repo.calls != 0 {
				t.Fatal("invalid command reached repository")
			}
			if version, err := invoke(actor, target, 1, domain.StatusBlocked); err != nil || version != 2 || repo.actor != actor {
				t.Fatal(version, err)
			}
			if action == "status" && repo.change.ActorID != actor.UserID || action == "delete" && repo.deletion.ActorID != actor.UserID {
				t.Fatal("caller controlled audit attribution")
			}
			for _, failure := range []error{domain.ErrLastAdministrator, domain.ErrAccountConflict, accessdomain.ErrFreshAuthRequired, errors.New("database unavailable")} {
				repo.err = failure
				if _, err := invoke(actor, target, 1, domain.StatusBlocked); !errors.Is(err, failure) {
					t.Fatal("error contract changed", err)
				}
			}
		})
	}
}

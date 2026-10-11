package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type identityRepoFunc func(context.Context, domain.IdentityKey, bool) (*domain.User, error)

func (fn identityRepoFunc) ResolveIdentityAccount(ctx context.Context, key domain.IdentityKey, allow bool) (*domain.User, error) {
	return fn(ctx, key, allow)
}

func TestIdentityResolution(t *testing.T) {
	key := domain.IdentityKey{Issuer: "https://provider.example", Subject: "subject"}
	for _, allow := range []bool{false, true} {
		repo := identityRepoFunc(func(ctx context.Context, got domain.IdentityKey, registration bool) (*domain.User, error) {
			deadline, bounded := ctx.Deadline()
			if got != key || registration != allow || !bounded || time.Until(deadline) > 5*time.Second {
				t.Fatal("wrong key/policy or unbounded lookup")
			}
			return &domain.User{ID: "owner", Status: domain.StatusActive, AuthVersion: 7}, nil
		})
		user, err := NewIdentityResolution(repo).Resolve(t.Context(), key, allow)
		if err != nil || user.ID != "owner" || user.AuthVersion != 7 {
			t.Fatal(user, err)
		}
	}
	for _, status := range []domain.Status{domain.StatusPending, domain.StatusBlocked, domain.StatusActive} {
		repo := identityRepoFunc(func(context.Context, domain.IdentityKey, bool) (*domain.User, error) {
			user := &domain.User{Status: status}
			if status == domain.StatusActive {
				now := time.Now()
				user.DeletedAt = &now
			}
			return user, nil
		})
		user, err := NewIdentityResolution(repo).Resolve(t.Context(), key, true)
		if user != nil || !errors.Is(err, domain.ErrIdentityUnavailable) {
			t.Fatal("inactive account accepted", user, err)
		}
	}
}

func TestIdentityResolutionValidationAndFailure(t *testing.T) {
	repo := identityRepoFunc(func(context.Context, domain.IdentityKey, bool) (*domain.User, error) {
		t.Fatal("invalid identity reached repository")
		return nil, nil
	})
	if _, err := NewIdentityResolution(repo).Resolve(t.Context(), domain.IdentityKey{}, true); !errors.Is(err, domain.ErrInvalidIdentity) {
		t.Fatal(err)
	}
	failure := errors.New("dependency failed")
	repo = func(context.Context, domain.IdentityKey, bool) (*domain.User, error) { return nil, failure }
	user, err := NewIdentityResolution(repo).Resolve(t.Context(), domain.IdentityKey{Issuer: "i", Subject: "s"}, true)
	if user != nil || !errors.Is(err, failure) {
		t.Fatal("dependency failure hidden", user, err)
	}
}

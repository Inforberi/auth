package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/session/domain"
)

type managementRepoStub struct {
	calls int
	rows  []domain.Session
	err   error
}

func (r *managementRepoStub) ListOwnSessions(_ context.Context, user accountdomain.UserID, hash, before string, limit int) ([]domain.Session, error) {
	r.calls++
	if user != "owner" || hash != "hash" || limit != 51 {
		panic("incorrect list contract")
	}
	return r.rows, r.err
}

func (r *managementRepoStub) RevokeOwnSession(context.Context, accountdomain.UserID, string, string) error {
	r.calls++
	return r.err
}

func (r *managementRepoStub) RevokeOwnSessions(context.Context, accountdomain.UserID, string) error {
	r.calls++
	return r.err
}

func TestManagementValidationAndPage(t *testing.T) {
	ctx := context.Background()
	repo := &managementRepoStub{}
	s := NewManagement(repo)
	for _, id := range []string{"", "hash", "11111111-1111-4111-8111-11111111111g", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		if err := s.Revoke(ctx, "owner", "hash", id); !errors.Is(err, domain.ErrInvalidSessionID) {
			t.Fatal(err)
		}
		if id != "" {
			if _, err := s.List(ctx, "owner", "hash", id); !errors.Is(err, domain.ErrInvalidSessionID) {
				t.Fatal(err)
			}
		}
	}
	if repo.calls != 0 {
		t.Fatal("invalid input reached repository")
	}
	for i := range 51 {
		repo.rows = append(repo.rows, domain.Session{ID: fmt.Sprintf("%08d-1111-4111-8111-111111111111", i)})
	}
	page, err := s.List(ctx, "owner", "hash", "")
	if err != nil || len(page.Sessions) != 50 || page.NextCursor != repo.rows[49].ID {
		t.Fatalf("invalid page: %v %v", page, err)
	}
	repo.rows = nil
	page, err = s.List(ctx, "owner", "hash", page.NextCursor)
	if err != nil || page.NextCursor != "" {
		t.Fatal("end-of-page cursor")
	}
	repo.err = errors.New("dependency")
	if err := s.LogoutAll(ctx, "owner", "hash"); !errors.Is(err, repo.err) {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "owner", "hash", "11111111-1111-4111-8111-111111111111"); !errors.Is(err, repo.err) {
		t.Fatal(err)
	}
}

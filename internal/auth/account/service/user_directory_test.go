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

type directoryRepository struct {
	users  []UserSummary
	query  UserListQuery
	actor  accessservice.Principal
	target domain.UserID
	err    error
	calls  int
}

func (r *directoryRepository) ListUsers(ctx context.Context, actor accessservice.Principal, query UserListQuery) ([]UserSummary, error) {
	r.calls++
	r.actor, r.query = actor, query
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 3*time.Second {
		return nil, errors.New("missing query deadline")
	}
	return r.users, r.err
}

func (r *directoryRepository) ReadUser(_ context.Context, actor accessservice.Principal, id domain.UserID) (UserDetail, error) {
	r.calls++
	r.actor, r.target = actor, id
	return UserDetail{}, r.err
}

func TestUserDirectoryValidationAndPagination(t *testing.T) {
	actor := accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	now := time.Date(2026, 10, 15, 12, 30, 0, 123456000, time.UTC)
	repo := &directoryRepository{users: []UserSummary{
		{ID: "33333333-3333-4333-8333-333333333333", CreatedAt: now},
		{ID: "22222222-2222-4222-8222-222222222222", CreatedAt: now},
		{ID: "11111111-1111-4111-8111-111111111111", CreatedAt: now.Add(-time.Second)},
	}}
	s := NewUserDirectory(repo)
	page, err := s.List(context.Background(), actor, UserListInput{Limit: 2, Status: domain.StatusActive, Email: " USER@example.com "})
	if err != nil || len(page.Users) != 2 || page.NextCursor == "" || repo.query.Email != "user@example.com" || repo.actor != actor {
		t.Fatal("page/normalization/authority", page, err)
	}
	before := page.NextCursor
	repo.users = nil
	page, err = s.List(context.Background(), actor, UserListInput{Limit: 2, Before: before})
	if err != nil || page.Users == nil || len(page.Users) != 0 || page.NextCursor != "" || repo.query.BeforeCreatedAt == nil || !repo.query.BeforeCreatedAt.Equal(now) || repo.query.BeforeID != "22222222-2222-4222-8222-222222222222" {
		t.Fatal("exclusive cursor/empty page", repo.query, page, err)
	}
	for _, input := range []UserListInput{
		{Limit: 0},
		{Limit: 101},
		{Limit: 1, Status: "deleted"},
		{Limit: 1, Email: "bad"},
		{Limit: 1, Before: "bad!"},
		{Limit: 1, Before: strings.Repeat("a", 193)},
		{Limit: 1, Before: userCursor(now, "not-a-uuid")},
	} {
		calls := repo.calls
		if _, err := s.List(context.Background(), actor, input); err == nil || calls != repo.calls {
			t.Fatal("invalid query reached SQL", input, err)
		}
	}
	calls := repo.calls
	if _, err := s.Read(context.Background(), actor, "bad"); !errors.Is(err, domain.ErrInvalidUserQuery) || calls != repo.calls {
		t.Fatal("invalid target reached SQL", err)
	}
	if _, err := s.List(context.Background(), accessservice.Principal{}, UserListInput{Limit: 1}); !errors.Is(err, accessdomain.ErrForbidden) || calls != repo.calls {
		t.Fatal("invalid actor reached SQL", err)
	}
	repo.err = errors.New("SQL unavailable")
	if _, err := s.Read(context.Background(), actor, actor.UserID); !errors.Is(err, repo.err) || repo.target != actor.UserID {
		t.Fatal("read swallowed repository result", err)
	}
}

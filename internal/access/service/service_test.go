package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

type fakeRepository struct {
	Repository
	calls   int
	allowed bool
	err     error
}

func (r *fakeRepository) HasPermission(ctx context.Context, _ Principal, _ domain.PermissionKey) (bool, error) {
	r.calls++
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 3*time.Second {
		return false, errors.New("missing operation budget")
	}
	return r.allowed, r.err
}

func (r *fakeRepository) CreateRole(_ context.Context, input CreateRoleInput) (domain.Role, error) {
	r.calls++
	return domain.Role{Key: input.Key}, r.err
}

func (r *fakeRepository) UpdateRole(_ context.Context, _ UpdateRoleInput) (domain.Role, error) {
	r.calls++
	return domain.Role{}, r.err
}

func (r *fakeRepository) ChangeAssignment(_ context.Context, _ AssignmentInput) (int64, error) {
	r.calls++
	return 2, r.err
}

func TestServiceBoundaries(t *testing.T) {
	catalog, err := settings.NewCatalog([]settings.Permission{{Key: "reports.read", Name: "Read reports"}})
	if err != nil {
		t.Fatal(err)
	}
	repo := &fakeRepository{allowed: true}
	svc := New(repo, catalog)
	actor := Principal{UserID: "00000000-0000-0000-0000-000000000001", TokenHash: strings.Repeat("a", 64)}
	if err := svc.Authorize(context.Background(), actor, "reports.read"); err != nil {
		t.Fatal(err)
	}
	before := repo.calls
	if err := svc.Authorize(context.Background(), actor, "unknown"); !errors.Is(err, domain.ErrForbidden) || repo.calls != before {
		t.Fatal("unknown permission reached storage")
	}
	input := CreateRoleInput{Actor: actor, Key: "reader", Name: "Reader", Permissions: []domain.PermissionKey{"unknown"}}
	if _, err := svc.CreateRole(context.Background(), input); !errors.Is(err, domain.ErrInvalidPermission) || repo.calls != before {
		t.Fatal("unknown role permission reached storage")
	}
	input.Permissions = []domain.PermissionKey{"reports.read"}
	if _, err := svc.CreateRole(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	before = repo.calls
	assignment := AssignmentInput{Actor: actor, UserID: actor.UserID, RoleID: "00000000-0000-0000-0000-000000000002", ExpectedAccessVersion: 1, ExpectedRoleVersion: 1, Grant: true}
	if _, err := svc.ChangeAssignment(context.Background(), assignment); !errors.Is(err, domain.ErrForbidden) || repo.calls != before {
		t.Fatal("self grant reached storage")
	}
	assignment.Grant = false
	if _, err := svc.ChangeAssignment(context.Background(), assignment); err != nil {
		t.Fatal(err)
	}
	repo.allowed = false
	if err := svc.Authorize(context.Background(), actor, "reports.read"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatal(err)
	}
	repo.err = errors.New("storage unavailable")
	if err := svc.Authorize(context.Background(), actor, "reports.read"); !errors.Is(err, repo.err) {
		t.Fatal("storage failure was hidden")
	}
}

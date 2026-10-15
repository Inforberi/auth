package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type queryRepository struct {
	Repository
	access    domain.UserAccess
	err       error
	reads     int
	actor     Principal
	target    accountdomain.UserID
	knownKeys []domain.PermissionKey
}

func (r *queryRepository) ReadAccess(context.Context, Principal, []domain.PermissionKey) (domain.UserAccess, error) {
	return r.access, r.err
}

func (r *queryRepository) ReadRole(context.Context, domain.RoleID) (domain.Role, error) {
	r.reads++
	return domain.Role{Key: "reader"}, nil
}

func (r *queryRepository) ListRoles(context.Context, string, int) ([]domain.Role, error) {
	r.reads++
	return []domain.Role{}, nil
}

func (r *queryRepository) ReadAssignments(_ context.Context, actor Principal, target accountdomain.UserID, known []domain.PermissionKey) (domain.UserAccess, error) {
	r.reads++
	r.actor, r.target, r.knownKeys = actor, target, known
	return r.access, r.err
}

func TestManagementQueries(t *testing.T) {
	catalog, err := settings.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := &queryRepository{}
	svc := New(repo, catalog)
	actor := Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}
	role := domain.RoleID("22222222-2222-4222-8222-222222222222")
	for _, permission := range []domain.PermissionKey{"", settings.RolesManage, settings.AssignmentsManage} {
		repo.access.Permissions = []domain.PermissionKey{permission}
		before := repo.reads
		_, catalogErr := svc.PermissionCatalog(context.Background(), actor)
		_, roleErr := svc.ReadManagedRole(context.Background(), actor, role)
		_, listErr := svc.ListManagedRoles(context.Background(), actor, "", 50)
		if permission == "" {
			if !errors.Is(catalogErr, domain.ErrForbidden) || !errors.Is(roleErr, domain.ErrForbidden) || !errors.Is(listErr, domain.ErrForbidden) || repo.reads != before {
				t.Fatal("unprivileged queries reached role storage")
			}
		} else if catalogErr != nil || roleErr != nil || listErr != nil || repo.reads != before+2 {
			t.Fatal("management reader denied", catalogErr, roleErr, listErr)
		}
	}
	before := repo.reads
	if _, err := svc.ReadManagedRole(context.Background(), actor, "bad"); !errors.Is(err, domain.ErrInvalidRole) || repo.reads != before {
		t.Fatal("invalid role reached storage", err)
	}
	if _, err := svc.ListManagedRoles(context.Background(), actor, "", 101); !errors.Is(err, domain.ErrInvalidRole) || repo.reads != before {
		t.Fatal("unbounded list reached storage", err)
	}
	if _, err := svc.AssignmentAccess(context.Background(), actor, "bad"); !errors.Is(err, domain.ErrInvalidRole) || repo.reads != before {
		t.Fatal("invalid target reached storage", err)
	}
	target := accountdomain.UserID(role)
	if _, err := svc.AssignmentAccess(context.Background(), actor, target); err != nil || repo.actor != actor || repo.target != target || len(repo.knownKeys) != 3 {
		t.Fatal("assignment query lost authority, target or catalog", err)
	}
	repo.err = errors.New("SQL unavailable")
	if _, err := svc.PermissionCatalog(context.Background(), actor); !errors.Is(err, repo.err) {
		t.Fatal("dependency failure ignored", err)
	}
}

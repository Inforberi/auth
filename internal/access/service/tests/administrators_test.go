package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
)

type administratorRepository struct {
	accessservice.Repository
	calls int
	input accessservice.AdministratorInput
	err   error
}

func (r *administratorRepository) ChangeAdministrator(ctx context.Context, input accessservice.AdministratorInput) (int64, error) {
	r.calls++
	r.input = input
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 3*time.Second {
		panic("unbounded administrator mutation")
	}
	return 2, r.err
}

func TestAdministratorValidation(t *testing.T) {
	catalog, err := settings.NewCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := &administratorRepository{}
	svc := accessservice.New(repo, catalog)
	input := accessservice.AdministratorInput{Actor: accessservice.Principal{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64)}, UserID: "22222222-2222-4222-8222-222222222222", ExpectedAuthVersion: 1, ExpectedAccessVersion: 1, ExpectedRoleVersion: 1, Grant: true}
	for _, mutate := range []func(*accessservice.AdministratorInput){
		func(i *accessservice.AdministratorInput) { i.Actor.TokenHash = "bad" }, func(i *accessservice.AdministratorInput) { i.UserID = i.Actor.UserID },
		func(i *accessservice.AdministratorInput) { i.UserID = "bad" }, func(i *accessservice.AdministratorInput) { i.ExpectedAuthVersion = 0 },
		func(i *accessservice.AdministratorInput) { i.ExpectedAccessVersion = 0 }, func(i *accessservice.AdministratorInput) { i.ExpectedRoleVersion = 0 },
	} {
		bad := input
		mutate(&bad)
		if _, err := svc.ChangeAdministrator(context.Background(), bad); err == nil || repo.calls != 0 {
			t.Fatal("invalid input reached SQL", err)
		}
	}
	if version, err := svc.ChangeAdministrator(context.Background(), input); err != nil || version != 2 || repo.input != input {
		t.Fatal(version, err)
	}
	input.UserID = input.Actor.UserID
	input.Grant = false
	if _, err := svc.ChangeAdministrator(context.Background(), input); err != nil {
		t.Fatal("self-revoke must reach SQL guard", err)
	}
	for _, failure := range []error{domain.ErrForbidden, domain.ErrFreshAuthRequired, domain.ErrConflict, errors.New("SQL unavailable")} {
		repo.err = failure
		if _, err := svc.ChangeAdministrator(context.Background(), input); !errors.Is(err, failure) {
			t.Fatal("error changed", err)
		}
	}
}

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type deletionRepoStub struct {
	calls int
	err   error
	input domain.AccountDeletion
}

func (r *deletionRepoStub) DeleteAccount(ctx context.Context, input domain.AccountDeletion) (domain.AuthVersion, error) {
	r.calls++
	r.input = input
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		panic("unbounded deletion")
	}
	if r.err != nil {
		return 0, r.err
	}
	return input.ExpectedVersion + 1, nil
}

func TestAccountDeletion(t *testing.T) {
	valid := domain.AccountDeletion{UserID: "11111111-1111-4111-8111-111111111111", ActorID: "22222222-2222-4222-8222-222222222222", ExpectedVersion: 1}
	for _, input := range []domain.AccountDeletion{
		{UserID: valid.UserID, ActorID: valid.ActorID},
		{UserID: "invalid", ActorID: valid.ActorID, ExpectedVersion: 1},
		{UserID: valid.UserID, ExpectedVersion: 1},
	} {
		repo := &deletionRepoStub{}
		version, err := NewDeletion(repo).Delete(context.Background(), input)
		if !errors.Is(err, domain.ErrInvalidAccountDeletion) || version != 0 || repo.calls != 0 {
			t.Fatal("invalid deletion reached storage", err)
		}
	}
	repo := &deletionRepoStub{}
	version, err := NewDeletion(repo).Delete(context.Background(), valid)
	if err != nil || version != 2 || repo.input != valid {
		t.Fatal("deletion contract", version, err)
	}
	for _, failure := range []error{domain.ErrAccountConflict, domain.ErrAccountNotFound, errors.New("storage failure")} {
		repo.err = failure
		version, err := NewDeletion(repo).Delete(context.Background(), valid)
		if version != 0 || !errors.Is(err, failure) {
			t.Fatal("deletion error lost", version, err)
		}
	}
}

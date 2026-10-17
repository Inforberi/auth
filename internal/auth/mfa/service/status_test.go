package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type statusRepository struct {
	Repository
	calls int
	err   error
	proof Proof
}

func (r *statusRepository) Status(_ context.Context, proof Proof) (*SecurityStatus, error) {
	r.calls++
	r.proof = proof
	return &SecurityStatus{TOTPEnabled: true, RecoveryCodesRemaining: 3}, r.err
}

func TestStatusIsAReadWithoutFactorBudgets(t *testing.T) {
	repo := &statusRepository{}
	s := New(repo, nil, nil, nil, "Auth")
	if _, err := s.Status(context.Background(), Proof{}); !errors.Is(err, domain.ErrProofRequired) || repo.calls != 0 {
		t.Fatal("invalid principal reached SQL", err)
	}
	proof := Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 2}
	result, err := s.Status(context.Background(), proof)
	if err != nil || result.RecoveryCodesRemaining != 3 || repo.proof != proof || repo.calls != 1 {
		t.Fatal(result, err)
	}
	repo.err = domain.ErrUnavailable
	if _, err := s.Status(context.Background(), proof); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("SQL failure hidden", err)
	}
}

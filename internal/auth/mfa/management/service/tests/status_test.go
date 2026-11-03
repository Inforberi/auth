package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfamanagement "github.com/Inforberi/financial-intelligence/internal/auth/mfa/management/service"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type statusRepository struct {
	mfamanagement.Repository
	calls int
	err   error
	proof mfaservice.Proof
}

func (r *statusRepository) Status(_ context.Context, proof mfaservice.Proof) (*mfamanagement.SecurityStatus, error) {
	r.calls++
	r.proof = proof
	return &mfamanagement.SecurityStatus{TOTPEnabled: true, RecoveryCodesRemaining: 3}, r.err
}

func TestStatusIsAReadWithoutFactorBudgets(t *testing.T) {
	repo := &statusRepository{}
	s := mfamanagement.New(repo, nil, nil, nil, "Auth")
	if _, err := s.Status(context.Background(), mfaservice.Proof{}); !errors.Is(err, domain.ErrProofRequired) || repo.calls != 0 {
		t.Fatal("invalid principal reached SQL", err)
	}
	proof := mfaservice.Proof{UserID: "11111111-1111-4111-8111-111111111111", TokenHash: strings.Repeat("a", 64), AuthVersion: 2}
	result, err := s.Status(context.Background(), proof)
	if err != nil || result.RecoveryCodesRemaining != 3 || repo.proof != proof || repo.calls != 1 {
		t.Fatal(result, err)
	}
	repo.err = domain.ErrUnavailable
	if _, err := s.Status(context.Background(), proof); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatal("SQL failure hidden", err)
	}
}

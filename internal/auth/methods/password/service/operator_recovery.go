package service

import (
	"context"
	"fmt"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type OperatorRecoveryTarget struct {
	Database    string
	Operator    string
	Status      accountdomain.Status
	AuthVersion int64
}

type operatorRecoveryRepository interface {
	OperatorRecoveryTarget(context.Context, accountdomain.UserID) (*OperatorRecoveryTarget, error)
	ResetAdministratorPassword(context.Context, domain.OperatorRecovery, string) (int64, error)
}

type OperatorRecoveryService struct {
	repo operatorRecoveryRepository
	hash hasher
}

func NewOperatorRecovery(repo operatorRecoveryRepository, hash hasher) *OperatorRecoveryService {
	return &OperatorRecoveryService{repo: repo, hash: hash}
}

func (s *OperatorRecoveryService) Preview(ctx context.Context, user accountdomain.UserID) (*OperatorRecoveryTarget, error) {
	if !accountdomain.ValidUserID(user) {
		return nil, domain.ErrOperatorRecoveryInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.OperatorRecoveryTarget(ctx, user)
}

// Reset is operator-only, not an authenticated-user or HTTP recovery authority.
func (s *OperatorRecoveryService) Reset(ctx context.Context, request domain.OperatorRecovery, password []byte) (int64, error) {
	if err := request.Validate(); err != nil {
		return 0, err
	}
	if err := domain.ValidatePassword(string(password)); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrOperatorPasswordPolicy, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Admission avoids Argon2 for unauthorized callers; the transaction repeats current authority/version checks.
	target, err := s.repo.OperatorRecoveryTarget(ctx, request.UserID)
	if err != nil {
		return 0, err
	}
	if target.AuthVersion != request.ExpectedVersion {
		return 0, domain.ErrOperatorRecoveryConflict
	}
	hash, err := s.hash.GenerateHash(ctx, password)
	if err != nil {
		return 0, err
	}
	return s.repo.ResetAdministratorPassword(ctx, request, hash)
}

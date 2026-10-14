package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
)

type RecoveryTarget struct {
	Database, Operator, State string
	AuthVersion               int64
	ExpiresAt                 time.Time
}

type RecoveryOperatorRepository interface {
	RecoveryTarget(context.Context, accountdomain.UserID, string) (*RecoveryTarget, error)
	DecideRecovery(context.Context, domain.RecoveryDecision) error
}

type RecoveryOperator struct{ repo RecoveryOperatorRepository }

func NewRecoveryOperator(repo RecoveryOperatorRepository) *RecoveryOperator {
	return &RecoveryOperator{repo: repo}
}

func (s *RecoveryOperator) Preview(ctx context.Context, user accountdomain.UserID, request string) (*RecoveryTarget, error) {
	if !accountdomain.ValidUserID(user) || !accountdomain.ValidUserID(accountdomain.UserID(request)) {
		return nil, domain.ErrRecoveryOperatorInput
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.RecoveryTarget(ctx, user, request)
}

func (s *RecoveryOperator) Decide(ctx context.Context, input domain.RecoveryDecision) error {
	if err := input.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.repo.DecideRecovery(ctx, input)
}

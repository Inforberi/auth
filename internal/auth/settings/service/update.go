package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type UpdateInput struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Policy          domain.Policy
}

func (s *Service) Update(ctx context.Context, input UpdateInput) (domain.Snapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.Snapshot{}, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return domain.Snapshot{}, domain.ErrInvalidPolicy
	}
	if err := input.Policy.Validate(); err != nil {
		return domain.Snapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.Update(ctx, input)
}

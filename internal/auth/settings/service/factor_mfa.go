package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type FactorMFAUpdate struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Allowed         bool
}

// Factor-specific readiness and SQL guards stay in the repositories.
type factorMFA[Snapshot any] struct {
	read  func(context.Context, accessservice.Principal) (Snapshot, error)
	write func(context.Context, FactorMFAUpdate, bool) (Snapshot, error)
	ready bool
}

func (s *factorMFA[Snapshot]) Read(ctx context.Context, actor accessservice.Principal) (Snapshot, error) {
	var empty Snapshot
	if actor.Validate() != nil {
		return empty, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.read(ctx, actor)
}

func (s *factorMFA[Snapshot]) Update(ctx context.Context, input FactorMFAUpdate) (Snapshot, error) {
	var empty Snapshot
	if input.Actor.Validate() != nil {
		return empty, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return empty, domain.ErrInvalidMFAPolicy
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.write(ctx, input, s.ready)
}

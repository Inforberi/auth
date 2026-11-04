package service

import (
	"context"
	"time"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

// RoleReconciliation keeps the receipt payload private to its persistence owner.
type RoleReconciliation interface {
	ReadReceipt(context.Context) (bool, error)
	RecordReceipt(context.Context) error
}

func (s *Roles) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleOutcome, error) {
	known, err := s.repo.ReadRoleOutcome(ctx, actor, project, operation)
	if err != nil || known.Committed {
		return known, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	job, err := s.repo.PrepareRoleReconciliation(ctx, actor, project, operation)
	if err != nil {
		return domain.RoleOutcome{}, err
	}
	if job == nil {
		return domain.RoleOutcome{}, domain.ErrUnavailable
	}
	found, err := job.ReadReceipt(ctx)
	if err != nil {
		return domain.RoleOutcome{}, err
	}
	if found {
		if err := job.RecordReceipt(ctx); err != nil {
			return domain.RoleOutcome{}, err
		}
	}
	return s.repo.ReadRoleOutcome(ctx, actor, project, operation)
}

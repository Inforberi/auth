package service

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

type RoleRepository interface {
	PrepareRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationIntent, error)
	ExecuteRoleCreation(context.Context, operatordomain.Principal, domain.RoleCreation) (domain.RoleCreationResult, error)
	ReadRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error)
	ReconcileRoleOutcome(context.Context, operatordomain.Principal, domain.ID, domain.ID) (domain.RoleCreationOutcome, error)
}

type Roles struct{ repo RoleRepository }

func NewRoles(repo RoleRepository) *Roles { return &Roles{repo: repo} }

func (s *Roles) CreateRole(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationResult, error) {
	if _, err := s.repo.PrepareRoleCreation(ctx, actor, command); err != nil {
		return domain.RoleCreationResult{}, err
	}
	return s.repo.ExecuteRoleCreation(ctx, actor, command)
}

func (s *Roles) ReadRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleCreationOutcome, error) {
	return s.repo.ReadRoleOutcome(ctx, actor, project, operation)
}

func (s *Roles) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleCreationOutcome, error) {
	return s.repo.ReconcileRoleOutcome(ctx, actor, project, operation)
}

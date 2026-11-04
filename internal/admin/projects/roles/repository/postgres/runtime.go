package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalogpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type RuntimeRoles struct {
	*catalogpostgres.Repository
	registry    *projectruntime.Registry
	permissions settings.Catalog
}

func NewRuntimeRoles(repo *catalogpostgres.Repository, registry *projectruntime.Registry, permissions settings.Catalog) *RuntimeRoles {
	return &RuntimeRoles{Repository: repo, registry: registry, permissions: permissions}
}

func (r *RuntimeRoles) ExecuteRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationResult, error) {
	grant, err := r.AdmitRoleCreation(ctx, actor, command)
	if err != nil {
		return domain.RoleCreationResult{}, err
	}
	// Platform MFA readiness is not project readiness. Until project Auth assembly
	// supplies that capability, MFA-required roles fail closed in the transaction.
	return grant.ExecuteWithRuntime(ctx, r.registry, r.permissions, false)
}

func (r *RuntimeRoles) ExecuteRoleAssignment(ctx context.Context, actor operatordomain.Principal, command domain.RoleAssignment) (domain.RoleAssignmentResult, error) {
	grant, err := r.AdmitRoleAssignment(ctx, actor, command)
	if err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	return grant.ExecuteWithRuntime(ctx, r.registry, r.permissions, false)
}

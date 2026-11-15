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
	readiness   Readiness
}

func NewRuntimeRoles(repo *catalogpostgres.Repository, registry *projectruntime.Registry, permissions settings.Catalog) *RuntimeRoles {
	return &RuntimeRoles{Repository: repo, registry: registry, permissions: permissions}
}

func (r *RuntimeRoles) ExecuteRoleCreation(ctx context.Context, actor operatordomain.Principal, command domain.RoleCreation) (domain.RoleCreationResult, error) {
	var ready bool
	if command.MFARequired {
		var err error
		ready, err = r.projectMFAReady(ctx, actor, domain.DirectoryTarget{ProjectID: command.ProjectID, ExpectedVersion: command.ExpectedVersion, ExpectedGeneration: command.ExpectedGeneration}, operatordomain.AccessManage)
		if err != nil {
			return domain.RoleCreationResult{}, err
		}
	}
	grant, err := r.AdmitRoleCreation(ctx, actor, command)
	if err != nil {
		return domain.RoleCreationResult{}, err
	}
	return grant.ExecuteWithRuntime(ctx, r.registry, r.permissions, ready)
}

func (r *RuntimeRoles) ExecuteRoleAssignment(ctx context.Context, actor operatordomain.Principal, command domain.RoleAssignment) (domain.RoleAssignmentResult, error) {
	var ready bool
	if command.Action == domain.RoleGrant {
		var err error
		ready, err = r.projectMFAReady(ctx, actor, domain.DirectoryTarget{ProjectID: command.ProjectID, ExpectedVersion: command.ExpectedVersion, ExpectedGeneration: command.ExpectedGeneration}, operatordomain.AccessManage)
		if err != nil {
			return domain.RoleAssignmentResult{}, err
		}
	}
	grant, err := r.AdmitRoleAssignment(ctx, actor, command)
	if err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	return grant.ExecuteWithRuntime(ctx, r.registry, r.permissions, ready)
}

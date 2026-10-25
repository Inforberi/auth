package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

type RuntimeRoles struct {
	*Repository
	registry    *projectruntime.Registry
	permissions settings.Catalog
}

func NewRuntimeRoles(repo *Repository, registry *projectruntime.Registry, permissions settings.Catalog) *RuntimeRoles {
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

func (r *RuntimeRoles) ReconcileRoleOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.RoleOutcome, error) {
	return r.Repository.ReconcileRoleOutcome(ctx, actor, project, operation, r.registry)
}

// ExecuteWithRuntime keeps the exact admitted target leased through commit and outcome recording.
func (a *AdmittedRoleCreation) ExecuteWithRuntime(ctx context.Context, registry *projectruntime.Registry, permissions settings.Catalog, mfaReady bool) (domain.RoleCreationResult, error) {
	if a == nil || a.repository == nil || registry == nil {
		return domain.RoleCreationResult{}, domain.ErrConflict
	}
	key := projectruntime.Key{Binding: a.binding, Version: a.command.ExpectedVersion, Generation: a.command.ExpectedGeneration}
	return withProjectRuntime(ctx, registry, key, a.until, func(ctx context.Context, db projectruntime.Database) (domain.RoleCreationResult, error) {
		return a.Execute(ctx, db, permissions, mfaReady)
	})
}

package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

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

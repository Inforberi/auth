package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

// ExecuteWithRuntime keeps the exact admitted target leased through commit and outcome recording.
func (a *AdmittedRoleCreation) ExecuteWithRuntime(ctx context.Context, registry *projectruntime.Registry, permissions settings.Catalog, mfaReady bool) (domain.RoleCreationResult, error) {
	if a == nil || a.repository == nil || registry == nil {
		return domain.RoleCreationResult{}, domain.ErrConflict
	}
	ctx, cancel := context.WithDeadline(ctx, a.until)
	defer cancel()
	key := projectruntime.Key{Binding: a.binding, Version: a.command.ExpectedVersion, Generation: a.command.ExpectedGeneration}
	var result domain.RoleCreationResult
	err := registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
		var err error
		result, err = a.Execute(ctx, db, permissions, mfaReady)
		return err
	})
	return result, err
}

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func (a *AdmittedRoleAssignment) Execute(ctx context.Context, project RoleProjectDatabase, permissions settings.Catalog, mfaReady bool) (domain.RoleAssignmentResult, error) {
	if a == nil || a.repository == nil || a.used == nil || !a.actor.Valid() || !time.Now().Before(a.until) {
		return domain.RoleAssignmentResult{}, domain.ErrAdmissionExpired
	}
	var result domain.RoleAssignmentResult
	err := executeRoleTransaction(ctx, project, a.until, a.used, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = changePlatformAssignment(ctx, tx, a.actor, a.binding, a.command, permissions, mfaReady)
		return err
	})
	if err != nil {
		return domain.RoleAssignmentResult{}, err
	}
	result.CatalogRecorded = a.repository.recordAssignmentOutcome(ctx, a.command.OperationID, result.ReceiptAdmissionID, result.RoleAssignmentSnapshot) == nil
	return result, nil
}

func (a *AdmittedRoleAssignment) ExecuteWithRuntime(ctx context.Context, registry *projectruntime.Registry, permissions settings.Catalog, mfaReady bool) (domain.RoleAssignmentResult, error) {
	if a == nil || a.repository == nil || registry == nil {
		return domain.RoleAssignmentResult{}, domain.ErrConflict
	}
	key := projectruntime.Key{Binding: a.binding, Version: a.command.ExpectedVersion, Generation: a.command.ExpectedGeneration}
	return withRoleRuntime(ctx, registry, key, a.until, func(ctx context.Context, db projectruntime.Database) (domain.RoleAssignmentResult, error) {
		return a.Execute(ctx, db, permissions, mfaReady)
	})
}

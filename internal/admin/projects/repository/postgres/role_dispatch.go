package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

// Execute checks the actual transaction's project profile before mutation.
// Pool/transport provenance belongs to trusted assembly, never request input.
// Admission is final authorization: later platform revoke cannot undo this write.
func (a *AdmittedRoleCreation) Execute(ctx context.Context, project ProjectDatabase, permissions settings.Catalog, mfaReady bool) (domain.RoleCreationResult, error) {
	if a == nil || a.repository == nil || a.used == nil || !a.actor.Valid() || !time.Now().Before(a.until) {
		return domain.RoleCreationResult{}, domain.ErrAdmissionExpired
	}
	var result domain.RoleCreationResult
	err := executeProjectTransaction(ctx, project, a.until, a.used, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = CreatePlatformRoleInTransaction(ctx, tx, a.actor, a.binding, a.command, permissions, mfaReady)
		return err
	})
	if err != nil {
		return domain.RoleCreationResult{}, err
	}
	result.CatalogRecorded = a.recordOutcome(ctx, result) == nil
	return result, nil
}

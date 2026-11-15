package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapg "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

type DeletionPreview struct {
	ProjectID  domain.ID `json:"projectId" swaggertype:"string"`
	Name       string    `json:"name"`
	Version    int64     `json:"version"`
	Generation int64     `json:"generation"`
	HasUsers   bool      `json:"hasUsers"`
}

func (r *Repository) PreviewDeletion(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry) (DeletionPreview, error) {
	if err := target.Validate(); err != nil {
		return DeletionPreview{}, err
	}
	if registry == nil {
		return DeletionPreview{}, domain.ErrUnavailable
	}
	preview := DeletionPreview{ProjectID: target.ProjectID, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
	err := r.mutate(ctx, actor, operators.OperatorsManage, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var owner bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM platform.operator_realm WHERE initialized_at IS NOT NULL AND first_operator_id=$1)`, actor.UserID).Scan(&owner); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		if !owner {
			return operators.ErrForbidden
		}
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT name FROM platform.projects WHERE id=$1`, target.ProjectID).Scan(&preview.Name); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		key := projectruntime.Key{Binding: binding, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
		return registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
			project, err := db.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				return sqlerrors.Catalog(ctx, err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				_ = project.Rollback(cleanup) //nolint:gosec // Read-only transaction cleanup.
			}()
			if err := schemapg.CheckRuntime(ctx, project, binding); err != nil {
				return err
			}
			return sqlerrors.Catalog(ctx, project.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth.users)`).Scan(&preview.HasUsers))
		})
	})
	if err != nil {
		return DeletionPreview{}, err
	}
	return preview, nil
}

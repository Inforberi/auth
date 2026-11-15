package postgres

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	schemapostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/schema/postgres"
)

func (r *Repository) WriteProject(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, registry *projectruntime.Registry, permission operators.Permission, apply func(context.Context, pgx.Tx) error) error {
	if err := target.Validate(); err != nil {
		return err
	}
	if registry == nil {
		return domain.ErrUnavailable
	}
	return r.mutate(ctx, actor, permission, func(ctx context.Context, tx pgx.Tx, deadline time.Time) error {
		binding, _, err := lockProjectTarget(ctx, tx, target.ProjectID, target.ExpectedVersion, target.ExpectedGeneration)
		if err != nil {
			return err
		}
		key := projectruntime.Key{Binding: binding, Version: target.ExpectedVersion, Generation: target.ExpectedGeneration}
		return registry.Use(ctx, key, func(ctx context.Context, db projectruntime.Database) error {
			return executeProjectTransaction(ctx, db, deadline, new(atomic.Bool), func(ctx context.Context, projectTx pgx.Tx) error {
				if err := schemapostgres.CheckRuntime(ctx, projectTx, binding); err != nil {
					return err
				}
				if err := checkUserAuditGrants(ctx, projectTx, "auth.platform_management_audit", []string{"actor_id", "action", "target", "previous_value", "next_value"}); err != nil {
					return err
				}
				return apply(ctx, projectTx)
			})
		})
	})
}

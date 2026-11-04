package postgres

import (
	"context"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	catalogpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	roleservice "github.com/Inforberi/financial-intelligence/internal/admin/projects/roles/service"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

type roleReconciliation struct {
	source   *catalogpostgres.RoleReceiptSource
	registry *projectruntime.Registry
}

func (r *RuntimeRoles) PrepareRoleReconciliation(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (roleservice.RoleReconciliation, error) {
	if r.registry == nil {
		return nil, domain.ErrUnavailable
	}
	source, err := r.LoadRoleReceiptSource(ctx, actor, project, operation)
	if err != nil {
		return nil, err
	}
	return &roleReconciliation{source: source, registry: r.registry}, nil
}

func (r *roleReconciliation) ReadReceipt(ctx context.Context) (bool, error) {
	var found bool
	err := r.registry.Use(ctx, r.source.RuntimeKey(), func(ctx context.Context, db projectruntime.Database) error {
		var err error
		found, err = r.source.ReadReceipt(ctx, db)
		return err
	})
	return found, err
}

func (r *roleReconciliation) RecordReceipt(ctx context.Context) error {
	return r.source.RecordReceipt(ctx)
}

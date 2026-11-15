package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/managementaudit"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	retention "github.com/Inforberi/financial-intelligence/internal/auth/settings/retention/service"
)

func (r *RuntimeAuthPolicy) ReadProjectRetention(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (settings.RetentionSnapshot, error) {
	var result settings.RetentionSnapshot
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = settingspg.ReadRetentionInTransaction(ctx, tx)
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectRetention(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input retention.RetentionUpdateInput) (settings.RetentionSnapshot, error) {
	if input.ExpectedVersion < 1 || input.Policy.Validate() != nil {
		return settings.RetentionSnapshot{}, settings.ErrInvalidRetention
	}
	var result settings.RetentionSnapshot
	err := r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var err error
		result, err = settingspg.ApplyRetention(ctx, tx, input, func(before, after settings.RetentionSnapshot) error {
			return managementaudit.Record(ctx, tx, actor.UserID, "retention_updated", "retention", before, after)
		})
		if errors.Is(err, settings.ErrRetentionConfirmation) {
			return err
		}
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

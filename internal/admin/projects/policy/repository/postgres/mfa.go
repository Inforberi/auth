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
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func (r *RuntimeAuthPolicy) ReadProjectMFA(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (settings.MFASnapshot, error) {
	var result settings.MFASnapshot
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = settingspg.LoadMFAPolicyInTransaction(ctx, tx)
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectMFA(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input settingsservice.MFAChange) (settings.MFASnapshot, error) {
	if err := input.Policy.ValidateChange(input.ExpectedVersion); err != nil {
		return settings.MFASnapshot{}, err
	}
	var ready bool
	if r.readiness != nil && input.Policy.Mode != settings.MFAOptional {
		selected, err := r.ResolveProjectTarget(ctx, actor, target, operators.SettingsManage)
		if err != nil {
			return settings.MFASnapshot{}, err
		}
		report, err := r.readiness(ctx, selected.Key, selected.Origin)
		if err != nil {
			return settings.MFASnapshot{}, err
		}
		ready = report.MFAReady()
	}
	var result settings.MFASnapshot
	err := r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var err error
		result, err = settingspg.ApplyMFAPolicy(ctx, tx, input, ready, func(before, after settings.MFASnapshot) error {
			return managementaudit.Record(ctx, tx, actor.UserID, "mfa_updated", "mfa", before, after)
		})
		if errors.Is(err, settings.ErrInvalidMFAPolicy) {
			return err
		}
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

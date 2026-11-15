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
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	providers "github.com/Inforberi/financial-intelligence/internal/auth/settings/providers/service"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	smtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

type SettingsProfile func(context.Context, projectruntime.Key, string) (projectprofile.Endpoints, error)

func (r *RuntimeAuthPolicy) WithSettingsProfile(profile SettingsProfile) *RuntimeAuthPolicy {
	r.settingsProfile = profile
	return r
}

func (r *RuntimeAuthPolicy) projectSettings(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (projectprofile.Endpoints, error) {
	if r.settingsProfile == nil {
		return projectprofile.Endpoints{}, domain.ErrUnavailable
	}
	selected, err := r.ResolveProjectTarget(ctx, actor, target, operators.SettingsManage)
	if err != nil {
		return projectprofile.Endpoints{}, err
	}
	return r.settingsProfile(ctx, selected.Key, selected.Origin)
}

func (r *RuntimeAuthPolicy) ReadProjectSMTP(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (settings.SMTPSnapshot, error) {
	var result settings.SMTPSnapshot
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = settingspg.ReadSMTPInTransaction(ctx, tx)
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectSMTP(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input smtp.SMTPUpdateInput) (settings.SMTPSnapshot, error) {
	profile, err := r.projectSettings(ctx, actor, target)
	if err != nil {
		return settings.SMTPSnapshot{}, err
	}
	if profile.SMTPSettings == nil {
		return settings.SMTPSnapshot{}, domain.ErrUnavailable
	}
	prepared, err := profile.SMTPSettings.PrepareUpdate(input)
	if err != nil {
		return settings.SMTPSnapshot{}, err
	}
	var result settings.SMTPSnapshot
	err = r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var err error
		result, err = settingspg.ApplySMTP(ctx, tx, prepared, func(before, after settings.SMTPSnapshot) error {
			return managementaudit.Record(ctx, tx, actor.UserID, "smtp_updated", "smtp", before, after)
		})
		if errors.Is(err, settings.ErrInvalidSMTP) {
			return err
		}
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) ReadProjectProvider(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, name string) (settings.ProviderSnapshot, error) {
	if !settings.ValidProvider(name) {
		return settings.ProviderSnapshot{}, settings.ErrInvalidProvider
	}
	var result settings.ProviderSnapshot
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = settingspg.ReadProviderInTransaction(ctx, tx, name)
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectProvider(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, input providers.ProviderUpdateInput) (settings.ProviderSnapshot, error) {
	profile, err := r.projectSettings(ctx, actor, target)
	if err != nil {
		return settings.ProviderSnapshot{}, err
	}
	if profile.ProviderSettings == nil {
		return settings.ProviderSnapshot{}, domain.ErrUnavailable
	}
	prepared, err := profile.ProviderSettings.PrepareUpdate(input)
	if err != nil {
		return settings.ProviderSnapshot{}, err
	}
	var result settings.ProviderSnapshot
	err = r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		var err error
		result, err = settingspg.ApplyProvider(ctx, tx, prepared, func(before, after settings.ProviderSnapshot) error {
			return managementaudit.Record(ctx, tx, actor.UserID, "provider_updated", input.Provider, before, after)
		})
		if errors.Is(err, settings.ErrInvalidProvider) || errors.Is(err, settings.ErrProviderClientBound) {
			return err
		}
		return sqlerrors.Policy(ctx, err)
	})
	return result, err
}

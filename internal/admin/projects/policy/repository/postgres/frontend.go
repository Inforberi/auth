package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	accesspg "github.com/Inforberi/financial-intelligence/internal/access/repository/postgres"
	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type FrontendSettings struct {
	Version int64                   `json:"version"`
	Policy  settings.FrontendPolicy `json:"policy"`
	Source  settings.SourceMetadata `json:"source"`
}

func (r *RuntimeAuthPolicy) ReadProjectFrontends(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget) (FrontendSettings, error) {
	selected, err := r.ResolveProjectTarget(ctx, actor, target, operators.SettingsManage)
	if err != nil {
		return FrontendSettings{}, err
	}
	baseline := domain.FrontendDefaults(selected.Origin)
	var result FrontendSettings
	err = r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		snapshot, mode, err := settingspg.New(nil).FrontendPolicy().ReadProject(ctx, tx, baseline)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = FrontendSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: mode.Metadata()}
		return nil
	})
	return result, err
}

func (r *RuntimeAuthPolicy) UpdateProjectFrontends(ctx context.Context, actor operators.Principal, target domain.DirectoryTarget, expected int64, policy settings.FrontendPolicy) (FrontendSettings, error) {
	if expected < 1 {
		return FrontendSettings{}, settings.ErrInvalidFrontend
	}
	profile, err := r.projectSettings(ctx, actor, target)
	if err != nil {
		return FrontendSettings{}, err
	}
	if profile.Frontend == nil {
		return FrontendSettings{}, domain.ErrUnavailable
	}
	if err := domain.ValidateProjectFrontend(policy, profile.Origin, profile.FrontendOrigins); err != nil {
		return FrontendSettings{}, err
	}
	baseline := domain.FrontendDefaults(profile.Origin)

	var result FrontendSettings
	err = r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		snapshot, err := settingspg.New(nil).FrontendPolicy().ApplyProject(ctx, tx, actor.UserID, expected, baseline, policy)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = FrontendSettings{Version: snapshot.Version, Policy: snapshot.Policy, Source: settings.SourceAPI.Metadata()}
		return nil
	})
	return result, err
}

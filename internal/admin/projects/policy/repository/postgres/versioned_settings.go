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

func readVersionedSettings[P comparable, R any](ctx context.Context, r *RuntimeAuthPolicy, actor operators.Principal, target domain.DirectoryTarget,
	store settingspg.VersionedPolicy[P], baseline P, response func(settingspg.PolicySnapshot[P], settings.SourceMode) R,
) (R, error) {
	var result R
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operators.Permission{operators.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		snapshot, mode, err := store.ReadProject(ctx, tx, baseline)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = response(snapshot, mode)
		return nil
	})
	return result, err
}

func writeVersionedSettings[P comparable, R any](ctx context.Context, r *RuntimeAuthPolicy, actor operators.Principal, target domain.DirectoryTarget,
	store settingspg.VersionedPolicy[P], expected int64, baseline, policy P, response func(settingspg.PolicySnapshot[P], settings.SourceMode) R,
) (R, error) {
	var result R
	err := r.WriteProject(ctx, actor, target, r.registry, operators.SettingsManage, func(ctx context.Context, tx pgx.Tx) error {
		if err := accesspg.LockAccessChanges(ctx, tx); err != nil {
			return sqlerrors.Catalog(ctx, err)
		}
		snapshot, err := store.ApplyProject(ctx, tx, actor.UserID, expected, baseline, policy)
		if err != nil {
			return sqlerrors.Policy(ctx, err)
		}
		result = response(snapshot, settings.SourceAPI)
		return nil
	})
	return result, err
}

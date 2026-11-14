package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	catalogpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	configuration "github.com/Inforberi/financial-intelligence/internal/auth/settings/configuration/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func (r *RuntimeAuthPolicy) ReadAuthPolicyView(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (domain.AuthPolicyView, error) {
	var view domain.AuthPolicyView
	var selected catalogpostgres.DirectoryRuntime
	err := r.ReadDirectoryWithRuntime(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.SettingsManage}, &selected, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		view.Snapshot, err = settingspostgres.ReadPolicyInTransaction(ctx, tx)
		return sqlerrors.Policy(ctx, err)
	})
	if err != nil {
		return domain.AuthPolicyView{}, err
	}
	if configuration.EnvironmentOwned(ctx) {
		view.Snapshot.Source = settingsdomain.SourceENV
	}
	if r.readiness == nil {
		view.Readiness.Runtime = r.available
		return view, nil
	}
	// No project lease or policy lock survives this callback boundary.
	view.Readiness, err = r.readiness(ctx, selected.Key, selected.Origin)
	if err != nil {
		return domain.AuthPolicyView{}, err
	}
	if view.Readiness.PolicyVersion != view.Snapshot.Version {
		return domain.AuthPolicyView{}, settingsdomain.ErrPolicyConflict
	}
	current, err := r.ReadAuthPolicy(ctx, actor, target)
	if err != nil {
		return domain.AuthPolicyView{}, err
	}
	if current != view.Snapshot {
		return domain.AuthPolicyView{}, settingsdomain.ErrPolicyConflict
	}
	return view, nil
}

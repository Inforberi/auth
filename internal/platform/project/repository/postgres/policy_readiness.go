package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

func (r *RuntimeAuthPolicy) ReadAuthPolicyView(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (domain.AuthPolicyView, error) {
	var view domain.AuthPolicyView
	var selected directoryRuntime
	err := r.readDirectoryWithRuntime(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.SettingsManage}, &selected, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		view.Snapshot, err = settingspostgres.ReadPolicyInTransaction(ctx, tx)
		return policyReadError(ctx, err)
	})
	if err != nil {
		return domain.AuthPolicyView{}, err
	}
	if r.readiness == nil {
		view.Readiness.Runtime = r.available
		return view, nil
	}
	// No project lease or policy lock survives this callback boundary.
	view.Readiness, err = r.readiness(ctx, selected.key, selected.origin)
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

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/internal/sqlerrors"
	catalogpostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

type RuntimeAuthPolicy struct {
	*catalogpostgres.Repository
	registry  *projectruntime.Registry
	available settingsdomain.PolicyRuntime
	readiness AuthPolicyReadinessSource
}

type AuthPolicyReadinessSource func(context.Context, projectruntime.Key, string) (domain.AuthPolicyReadiness, error)

func (r *RuntimeAuthPolicy) WithReadiness(source AuthPolicyReadinessSource) *RuntimeAuthPolicy {
	copy := *r
	copy.readiness = source
	return &copy
}

func NewRuntimeAuthPolicy(repo *catalogpostgres.Repository, registry *projectruntime.Registry, available settingsdomain.PolicyRuntime) *RuntimeAuthPolicy {
	return &RuntimeAuthPolicy{Repository: repo, registry: registry, available: available}
}

func (r *RuntimeAuthPolicy) ReadAuthPolicy(ctx context.Context, actor operatordomain.Principal, target domain.DirectoryTarget) (settingsdomain.Snapshot, error) {
	var snapshot settingsdomain.Snapshot
	err := r.ReadDirectory(ctx, actor, target, r.registry, []operatordomain.Permission{operatordomain.SettingsManage}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		snapshot, err = settingspostgres.ReadPolicyInTransaction(ctx, tx)
		return sqlerrors.Policy(ctx, err)
	})
	if err != nil {
		return settingsdomain.Snapshot{}, err
	}
	return snapshot, nil
}

func (r *RuntimeAuthPolicy) UpdateAuthPolicy(ctx context.Context, actor operatordomain.Principal, command domain.AuthPolicyUpdate) (domain.AuthPolicyResult, error) {
	available := r.available
	var readiness *domain.AuthPolicyReadiness
	if r.readiness != nil {
		view, err := r.ReadAuthPolicyView(ctx, actor, domain.DirectoryTarget{ProjectID: command.ProjectID, ExpectedVersion: command.ExpectedVersion, ExpectedGeneration: command.ExpectedGeneration})
		if err != nil {
			return domain.AuthPolicyResult{}, err
		}
		available, readiness = view.Readiness.Runtime, &view.Readiness
	}
	admitted, err := r.AdmitAuthPolicy(ctx, actor, command)
	if err != nil {
		return domain.AuthPolicyResult{}, err
	}
	result, err := admitted.ExecuteWithRuntime(ctx, r.registry, available)
	result.Readiness = readiness
	return result, err
}

func (r *RuntimeAuthPolicy) ReadAuthPolicyOutcome(ctx context.Context, actor operatordomain.Principal, project, operation domain.ID) (domain.AuthPolicyOutcome, error) {
	return r.Repository.ReadAuthPolicyOutcome(ctx, actor, project, operation, r.registry)
}

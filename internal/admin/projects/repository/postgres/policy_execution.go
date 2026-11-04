package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policymutation "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres/mutation"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (a *AdmittedAuthPolicy) Execute(ctx context.Context, project ProjectDatabase, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if a == nil || a.used == nil || !a.actor.Valid() || !time.Now().Before(a.until) {
		return domain.AuthPolicyResult{}, domain.ErrAdmissionExpired
	}
	var result domain.AuthPolicyResult
	err := executeProjectTransaction(ctx, project, a.until, a.used, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		result, err = policymutation.ApplyAuthPolicyInTransaction(ctx, tx, a.actor, a.binding, a.command, available)
		return err
	})
	if err != nil {
		return domain.AuthPolicyResult{}, err
	}
	return result, nil
}

func (a *AdmittedAuthPolicy) ExecuteWithRuntime(ctx context.Context, registry *projectruntime.Registry, available settingsdomain.PolicyRuntime) (domain.AuthPolicyResult, error) {
	if a == nil || registry == nil {
		return domain.AuthPolicyResult{}, domain.ErrConflict
	}
	key := projectruntime.Key{Binding: a.binding, Version: a.command.ExpectedVersion, Generation: a.command.ExpectedGeneration}
	return withProjectRuntime(ctx, registry, key, a.until, func(ctx context.Context, db projectruntime.Database) (domain.AuthPolicyResult, error) {
		return a.Execute(ctx, db, available)
	})
}

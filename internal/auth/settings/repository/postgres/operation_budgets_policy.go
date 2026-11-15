package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) OperationBudgetsPolicy() VersionedPolicy[domain.OperationBudgetsPolicy] {
	return VersionedPolicy[domain.OperationBudgetsPolicy]{repo: r, table: operationBudgetsPolicyTable}
}

func (r *Repository) ProjectOperationBudgets(ctx context.Context, baseline domain.OperationBudgetsPolicy) (domain.OperationBudgetsPolicy, error) {
	var installed bool
	if err := r.db.QueryRow(ctx, `SELECT to_regclass('auth.operation_budgets_policy') IS NOT NULL`).Scan(&installed); err != nil || !installed {
		return baseline, err
	}
	var stored *domain.OperationBudgetsPolicy
	err := r.db.QueryRow(ctx, `SELECT CASE WHEN s.mode='api' THEN p.policy END FROM auth.operation_budgets_policy p
		JOIN auth.settings_source s ON s.singleton=p.singleton WHERE p.singleton`).Scan(&stored)
	if err != nil || stored == nil {
		return baseline, err
	}
	return *stored, stored.Validate(baseline)
}

package postgres

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (r *Repository) LoginBudgetPolicy() VersionedPolicy[domain.LoginBudgetPolicy] {
	return VersionedPolicy[domain.LoginBudgetPolicy]{repo: r, table: loginBudgetPolicyTable}
}

func (r *Repository) ProjectLoginBudget(ctx context.Context, baseline domain.LoginBudgetPolicy) (domain.LoginBudgetPolicy, error) {
	var installed bool
	if err := r.db.QueryRow(ctx, `SELECT to_regclass('auth.login_budget_policy') IS NOT NULL`).Scan(&installed); err != nil || !installed {
		return baseline, err
	}
	var stored *domain.LoginBudgetPolicy
	err := r.db.QueryRow(ctx, `SELECT CASE WHEN s.mode='api' THEN p.policy END FROM auth.login_budget_policy p
		JOIN auth.settings_source s ON s.singleton=p.singleton WHERE p.singleton`).Scan(&stored)
	if err != nil || stored == nil {
		return baseline, err
	}
	return *stored, stored.Validate(baseline)
}

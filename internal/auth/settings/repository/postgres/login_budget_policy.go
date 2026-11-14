package postgres

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

func (r *Repository) LoginBudgetPolicy() VersionedPolicy[domain.LoginBudgetPolicy] {
	return VersionedPolicy[domain.LoginBudgetPolicy]{repo: r, table: loginBudgetPolicyTable}
}

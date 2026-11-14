package postgres

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

func (r *Repository) OperationBudgetsPolicy() VersionedPolicy[domain.OperationBudgetsPolicy] {
	return VersionedPolicy[domain.OperationBudgetsPolicy]{repo: r, table: operationBudgetsPolicyTable}
}

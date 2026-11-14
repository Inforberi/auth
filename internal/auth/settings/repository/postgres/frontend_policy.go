package postgres

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

func (r *Repository) FrontendPolicy() VersionedPolicy[domain.FrontendPolicy] {
	return VersionedPolicy[domain.FrontendPolicy]{repo: r, table: frontendPolicyTable}
}

package postgres

import "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"

func (r *Repository) CredentialLifetimePolicy() VersionedPolicy[domain.CredentialLifetimePolicy] {
	return VersionedPolicy[domain.CredentialLifetimePolicy]{repo: r, table: credentialLifetimePolicyTable}
}

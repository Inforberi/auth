package postgres

import sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"

func (r *Repository) BrowserSessionPolicy() VersionedPolicy[sessions.BrowserPolicy] {
	return VersionedPolicy[sessions.BrowserPolicy]{repo: r, table: browserSessionPolicyTable}
}

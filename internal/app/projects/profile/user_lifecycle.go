package profile

import (
	projectaccount "github.com/Inforberi/financial-intelligence/internal/app/projects/account"
)

func (p *ProjectProfile) buildProfileUserLifecycle(cfg ProjectProfileConfig) {
	if !cfg.UserLifecycleEnabled {
		return
	}
	switch {
	case !cfg.BrowserEnabled:
		p.state("user_lifecycle", "browser_disabled")
	case p.mfaManagement == nil:
		p.state("user_lifecycle", "mfa_unavailable")
	default:
		p.userLifecycle = projectaccount.NewProjectUserLifecycle(p.runtimeBinding())
		p.state("user_lifecycle", "")
	}
}

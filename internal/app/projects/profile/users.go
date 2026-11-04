package profile

import (
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func (p *profileAssembly) buildProfileUserDirectory(cfg runtimeprofile.ProjectProfileConfig) {
	if !cfg.UserDirectoryEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("user_directory", "browser_disabled")
		return
	}
	p.userDirectory = projectaccount.NewProjectUserDirectory(p.runtimeBinding())
	p.state("user_directory", "")
}

func (p *profileAssembly) buildProfileUserLifecycle(cfg runtimeprofile.ProjectProfileConfig) {
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

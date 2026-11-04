package profile

import (
	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
)

func (p *ProjectProfile) buildProfileUserDirectory(cfg ProjectProfileConfig) {
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

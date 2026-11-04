package profile

import (
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
)

func (p *ProjectProfile) buildProfileMFASettings(cfg ProjectProfileConfig) {
	if !cfg.MFASettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("mfa_settings", "browser_disabled")
		return
	}
	p.mfaSettings = projectsettings.NewProjectMFASettings(p.runtimeBinding(), p.mfaManagement != nil)
	p.state("mfa_settings", "")
}

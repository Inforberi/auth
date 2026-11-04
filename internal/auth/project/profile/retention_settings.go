package profile

import (
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
)

func (p *ProjectProfile) buildProfileRetentionSettings(cfg ProjectProfileConfig) {
	if !cfg.RetentionSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("retention_settings_read", "browser_disabled")
		p.state("retention_settings_write", "browser_disabled")
		return
	}
	p.retentionSettings = projectsettings.NewProjectRetentionSettings(p.runtimeBinding())
	p.state("retention_settings_read", "")
	reason := ""
	if p.mfaManagement == nil {
		reason = "mfa_unavailable"
	}
	p.state("retention_settings_write", reason)
}

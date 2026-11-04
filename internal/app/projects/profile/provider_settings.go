package profile

import (
	projectsettings "github.com/Inforberi/financial-intelligence/internal/app/projects/settings"
)

func (p *ProjectProfile) buildProfileProviderSettings(cfg ProjectProfileConfig, root string) {
	if !cfg.ProviderSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("provider_settings_read", "browser_disabled")
		p.state("provider_settings_write", "browser_disabled")
		return
	}
	s := projectsettings.NewProjectProviderSettings(p.runtimeBinding())
	p.providerSettings = s
	p.state("provider_settings_read", "")
	if p.mfaManagement == nil {
		p.state("provider_settings_write", "mfa_unavailable")
		return
	}
	err := s.Configure(root)
	p.feature("provider_settings_write", err)
}

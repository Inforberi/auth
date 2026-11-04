package profile

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
)

func (p *ProjectProfile) buildProfileAuthSettings(cfg ProjectProfileConfig) {
	if !cfg.AuthSettingsEnabled {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("auth_settings_read", "browser_disabled")
		p.state("auth_settings_write", "browser_disabled")
		return
	}
	p.authSettings = projectsettings.NewProjectAuthSettings(p.runtimeBinding(), cfg.Timeout, func(ctx context.Context) (projectdomain.AuthPolicyReadiness, error) {
		return AssessProjectProfile(ctx, p.key, p.origin, cfg, p.deps)
	})
	p.state("auth_settings_read", "")
	reason := ""
	if p.mfaManagement == nil {
		reason = "mfa_unavailable"
	}
	p.state("auth_settings_write", reason)
}

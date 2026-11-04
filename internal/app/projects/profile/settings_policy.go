package profile

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
)

func (p *profileAssembly) buildProfileAuthSettings(cfg runtimeprofile.ProjectProfileConfig) {
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

func (p *profileAssembly) buildProfileMFASettings(cfg runtimeprofile.ProjectProfileConfig) {
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

func (p *profileAssembly) buildProfileRetentionSettings(cfg runtimeprofile.ProjectProfileConfig) {
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

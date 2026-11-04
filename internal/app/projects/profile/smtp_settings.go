package profile

import (
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/app/projects/settings"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

func (p *ProjectProfile) buildProfileSMTPSettings(cfg ProjectProfileConfig, root string, redisReady bool) {
	if cfg.SMTPSettings == nil {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("smtp_settings_read", "browser_disabled")
		p.state("smtp_settings_write", "browser_disabled")
		return
	}
	s := projectsettings.NewProjectSMTPSettings(p.runtimeBinding())
	p.smtpSettings = s
	p.state("smtp_settings_read", "")
	reason := ""
	switch {
	case p.mfaManagement == nil:
		reason = "mfa_unavailable"
	case !redisReady:
		reason = "redis_unavailable"
	default:
		source, err := projectapp.NewSMTP(p.key, root, cfg.SMTPSettings.AllowedTargets, projectapp.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
		if err == nil {
			gate := p.deps.SMTPTests
			if gate == nil {
				gate = settingssmtp.NewSMTPTestGate()
			}
			err = s.Configure(source, gate)
		}
		if err != nil {
			reason = "invalid_smtp_configuration"
		}
	}
	p.state("smtp_settings_write", reason)
}

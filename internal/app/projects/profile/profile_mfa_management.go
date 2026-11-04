package profile

import (
	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func configuredBrowserPolicies(cfg ProjectProfileConfig) []projectmethods.BrowserPolicy {
	views := make([]projectmethods.BrowserPolicy, 0, 4)
	if cfg.Password != nil {
		views = append(views, projectmethods.BrowserPolicy{Feature: "password", Session: cfg.Password.Session, MFA: cfg.Password.MFA})
	}
	if cfg.EmailOTP != nil {
		views = append(views, projectmethods.BrowserPolicy{Feature: "emailotp", Session: cfg.EmailOTP.Session, MFA: cfg.EmailOTP.MFA})
	}
	for _, provider := range []*projectmethods.ProjectOIDCConfig{cfg.Google, cfg.Telegram} {
		if provider != nil && provider.Enabled {
			views = append(views, projectmethods.BrowserPolicy{Feature: provider.Provider, Session: provider.Session, MFA: provider.MFA})
		}
	}
	return views
}

func (p *ProjectProfile) buildProfileMFAManagement(cfg ProjectProfileConfig, root string, redisReady bool) {
	if !cfg.BrowserEnabled {
		return
	}
	views := configuredBrowserPolicies(cfg)
	enabled := false
	for _, view := range views {
		enabled = enabled || view.MFA.Enabled
	}
	if !enabled {
		return
	}
	base := views[0]
	for _, view := range views[1:] {
		if view.Session != base.Session || view.MFA != base.MFA {
			p.state("mfa_management", "inconsistent_browser_policy")
			return
		}
	}
	if !redisReady {
		p.state("mfa_management", "redis_unavailable")
		return
	}
	if err := projectmfa.ValidateProjectMFA(base.MFA); err != nil {
		p.feature("mfa_management", err)
		return
	}
	if err := base.Session.Validate(); err != nil {
		p.feature("mfa_management", err)
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err != nil {
		p.feature("mfa_management", err)
		return
	}
	var factory *projectmfa.ProjectMFALogin
	if p.mfa != nil {
		factory = p.mfa.Factory()
	} else {
		factory, err = projectmfa.NewProjectMFALogin(scope, root, base.MFA, base.Session, p.deps.Redis, base.Feature)
		if err != nil {
			p.feature("mfa_management", err)
			return
		}
	}
	p.mfaManagement = projectmfa.BindProjectMFA(factory, p.key, p.deps.Registry, p.deps.Reader, cfg.Timeout, p.featureReady("reauthentication"))
	p.state("mfa_management", "")
}

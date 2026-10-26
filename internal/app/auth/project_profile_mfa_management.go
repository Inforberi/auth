package auth

import "github.com/Inforberi/financial-intelligence/internal/infra/realmscope"

func configuredBrowserPolicies(cfg ProjectProfileConfig) []profileBrowserPolicy {
	views := make([]profileBrowserPolicy, 0, 4)
	if cfg.Password != nil {
		views = append(views, profileBrowserPolicy{"password", cfg.Password.Session, cfg.Password.MFA})
	}
	if cfg.EmailOTP != nil {
		views = append(views, profileBrowserPolicy{"emailotp", cfg.EmailOTP.Session, cfg.EmailOTP.MFA})
	}
	for _, provider := range []*ProjectOIDCConfig{cfg.Google, cfg.Telegram} {
		if provider != nil && provider.Enabled {
			views = append(views, profileBrowserPolicy{provider.Provider, provider.Session, provider.MFA})
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
		enabled = enabled || view.mfa.Enabled
	}
	if !enabled {
		return
	}
	base := views[0]
	for _, view := range views[1:] {
		if view.session != base.session || view.mfa != base.mfa {
			p.state("mfa_management", "inconsistent_browser_policy")
			return
		}
	}
	if !redisReady {
		p.state("mfa_management", "redis_unavailable")
		return
	}
	if err := validateProjectMFA(base.mfa); err != nil {
		p.feature("mfa_management", err)
		return
	}
	if err := base.session.Validate(); err != nil {
		p.feature("mfa_management", err)
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err != nil {
		p.feature("mfa_management", err)
		return
	}
	var factory *projectMFALogin
	if p.mfa != nil {
		factory = p.mfa.factory
	} else {
		factory, err = newProjectMFALogin(scope, root, base.mfa, base.session, p.deps.Redis, base.feature)
		if err != nil {
			p.feature("mfa_management", err)
			return
		}
	}
	p.mfaManagement = &projectMFA{factory: factory, key: p.key, registry: p.deps.Registry, reader: p.deps.Reader, timeout: cfg.Timeout, emailProof: p.featureReady("reauthentication")}
	p.state("mfa_management", "")
}

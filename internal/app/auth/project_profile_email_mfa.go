package auth

func (p *ProjectProfile) buildProfileEmailMFA(cfg ProjectProfileConfig) {
	if cfg.EmailMFA == nil {
		return
	}
	if err := cfg.EmailMFA.Validate(); err != nil {
		p.feature("email_mfa", err)
		return
	}
	if !cfg.BrowserEnabled || cfg.Password == nil || !cfg.Password.MFA.Enabled || !cfg.Password.MFA.RecoveryEnabled {
		p.state("email_mfa", "password_mfa_recovery_required")
		return
	}
	if p.mfaManagement == nil || p.mfaRecovery == nil {
		p.state("email_mfa", "mfa_recovery_unavailable")
		return
	}
	p.emailMFA = &projectEmailMFA{mfa: p.mfaManagement, mail: p.mfaRecovery.mail, cfg: *cfg.EmailMFA}
	p.state("email_mfa", "")
	if p.featureReady("password") {
		p.state("email_mfa_login", "")
	}
	if p.tokens != nil && p.tokens.native != nil && p.tokens.cfg.Native.PasswordEnabled {
		native := p.tokens.native
		native.emailMFA = &projectEmailMFA{mfa: &projectMFA{factory: native.mfa, key: p.key, registry: p.deps.Registry, reader: p.deps.Reader, timeout: cfg.Timeout}, mail: p.emailMFA.mail, cfg: *cfg.EmailMFA}
		if p.featureReady("native_password") {
			p.state("native_email_mfa", "")
		}
	}
}

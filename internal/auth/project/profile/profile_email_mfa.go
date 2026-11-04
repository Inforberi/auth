package profile

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
	p.emailMFA = p.mfaRecovery.NewEmailFactor(p.mfaManagement, *cfg.EmailMFA)
	p.state("email_mfa", "")
	if p.featureReady("password") {
		p.state("email_mfa_login", "")
	}
	if p.tokens != nil && p.tokens.NativePasswordEnabled() {
		p.tokens.BindEmailMFA(p.emailMFA, cfg.Timeout)
		if p.featureReady("native_password") {
			p.state("native_email_mfa", "")
		}
	}
}

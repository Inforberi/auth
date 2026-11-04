package profile

import (
	"context"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func (p *ProjectProfile) buildProfileMFARecovery(ctx context.Context, cfg ProjectProfileConfig, root string, redisReady bool) {
	requested := false
	for _, view := range configuredBrowserPolicies(cfg) {
		requested = requested || view.MFA.RecoveryEnabled
	}
	if !requested {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("mfa_recovery", "browser_disabled")
		return
	}
	mfa := p.mfa
	if mfa == nil {
		mfa = p.mfaManagement
	}
	if mfa == nil {
		p.state("mfa_recovery", "mfa_unavailable")
		return
	}
	if reason := p.mailReason(redisReady); reason != "" {
		p.state("mfa_recovery", reason)
		return
	}
	mail, err := projectaccount.NewProjectEmailRuntime(p.key, root, p.deps.Delivery.AllowedTargets(), projectbinding.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
	if err != nil {
		p.feature("mfa_recovery", err)
		return
	}
	recovery := projectmfa.NewProjectMFARecovery(mfa, mail)
	if err := recovery.CheckDependencies(ctx); err != nil {
		p.state("mfa_recovery", "recovery_dependencies_unavailable")
		return
	}
	p.mfaRecovery = recovery
	p.state("mfa_recovery", "")
}

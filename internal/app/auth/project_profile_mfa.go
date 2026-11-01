package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

type profileBrowserPolicy struct {
	feature string
	session sessionservice.Config
	mfa     mfaservice.Config
}

func (p *ProjectProfile) checkMFACapability(ctx context.Context, cfg ProjectProfileConfig) error {
	enabled := true
	if cfg.BrowserEnabled {
		for _, view := range configuredBrowserPolicies(cfg) {
			enabled = enabled && view.mfa.Enabled
		}
	}
	if cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil {
		enabled = enabled && cfg.Tokens.Native.MFA.Enabled
	}
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		return mfapostgres.New(pool).CheckEmailCapability(ctx, enabled, p.emailMFA != nil)
	})
}

func (p *ProjectProfile) bindProfileMFA(root string) {
	var views []profileBrowserPolicy
	if p.featureReady("password") {
		views = append(views, profileBrowserPolicy{"password", p.password.cfg.Session, p.password.cfg.MFA})
	}
	if p.featureReady("emailotp") {
		views = append(views, profileBrowserPolicy{"emailotp", p.emailOTP.cfg.Session, p.emailOTP.cfg.MFA})
	}
	for _, provider := range []*ProjectOIDC{p.google, p.telegram} {
		if provider != nil {
			views = append(views, profileBrowserPolicy{provider.cfg.Provider, provider.cfg.Session, provider.cfg.MFA})
		}
	}
	if len(views) == 0 {
		return
	}
	base := views[0]
	for _, view := range views[1:] {
		if view.session != base.session || view.mfa.Enabled != base.mfa.Enabled || view.mfa.Enabled && view.mfa != base.mfa {
			p.disableProfileBrowser(views, "inconsistent_browser_policy")
			return
		}
	}
	if !base.mfa.Enabled {
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err != nil {
		p.feature("mfa", err)
		p.disableProfileBrowser(views, "mfa_unavailable")
		return
	}
	factory, err := newProjectMFALogin(scope, root, base.mfa, base.session, p.deps.Redis, base.feature)
	if err != nil {
		p.feature("mfa", err)
		p.disableProfileBrowser(views, "mfa_unavailable")
		return
	}
	factory.config.AllowPrimary = func(method, issuer string) bool { return p.featureReady(settingsdomain.PrimaryMethod(method, issuer)) }
	p.mfa = &projectMFA{factory: factory, key: p.key, registry: p.deps.Registry, reader: p.deps.Reader, timeout: 30 * time.Second}
	p.state("mfa", "")
}

func (p *ProjectProfile) disableProfileBrowser(views []profileBrowserPolicy, reason string) {
	for _, method := range views {
		p.state(method.feature, reason)
	}
	p.password, p.google, p.telegram = nil, nil, nil
	if !p.featureReady("reauthentication") {
		p.emailOTP = nil
	}
}

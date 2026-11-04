package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/app/projects/mfa"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func (p *ProjectProfile) checkMFACapability(ctx context.Context, cfg ProjectProfileConfig) error {
	enabled := true
	if cfg.BrowserEnabled {
		for _, view := range configuredBrowserPolicies(cfg) {
			enabled = enabled && view.MFA.Enabled
		}
	}
	if cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil {
		enabled = enabled && cfg.Tokens.Native.MFA.Enabled
	}
	return p.deps.Registry.UsePool(ctx, p.key, func(ctx context.Context, pool *pgxpool.Pool) error {
		return mfapostgres.New(pool).CheckFactorCapability(ctx, enabled, p.emailMFA != nil, p.telegramMFA != nil)
	})
}

func (p *ProjectProfile) bindProfileMFA(root string) {
	var views []projectmethods.BrowserPolicy
	if p.featureReady("password") {
		views = append(views, p.password.BrowserPolicy())
	}
	if p.featureReady("emailotp") {
		views = append(views, p.emailOTP.BrowserPolicy())
	}
	for _, provider := range []*projectmethods.ProjectOIDC{p.google, p.telegram} {
		if provider != nil {
			views = append(views, provider.BrowserPolicy())
		}
	}
	p.bindBrowserMFA(root, views)
}

func (p *ProjectProfile) bindBrowserMFA(root string, views []projectmethods.BrowserPolicy) {
	if len(views) == 0 {
		return
	}
	base := views[0]
	for _, view := range views[1:] {
		if view.Session != base.Session || view.MFA.Enabled != base.MFA.Enabled || view.MFA.Enabled && view.MFA != base.MFA {
			p.disableProfileBrowser(views, "inconsistent_browser_policy")
			return
		}
	}
	if !base.MFA.Enabled {
		return
	}
	scope, err := realmscope.New("project", string(p.key.Binding.ProjectID))
	if err != nil {
		p.feature("mfa", err)
		p.disableProfileBrowser(views, "mfa_unavailable")
		return
	}
	factory, err := projectmfa.NewProjectMFALogin(scope, root, base.MFA, base.Session, p.deps.Redis, base.Feature)
	if err != nil {
		p.feature("mfa", err)
		p.disableProfileBrowser(views, "mfa_unavailable")
		return
	}
	factory.BindPrimary(func(method, issuer string) bool { return p.featureReady(settingsdomain.PrimaryMethod(method, issuer)) })
	p.mfa = projectmfa.BindProjectMFA(factory, p.key, p.deps.Registry, p.deps.Reader, 30*time.Second, false)
	p.state("mfa", "")
}

func (p *ProjectProfile) disableProfileBrowser(views []projectmethods.BrowserPolicy, reason string) {
	for _, method := range views {
		p.state(method.Feature, reason)
	}
	p.password, p.google, p.telegram = nil, nil, nil
	if !p.featureReady("reauthentication") {
		p.emailOTP = nil
	}
}

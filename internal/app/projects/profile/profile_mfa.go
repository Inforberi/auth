package profile

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	projectmfa "github.com/Inforberi/financial-intelligence/internal/auth/project/mfa"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
)

func (p *profileAssembly) checkMFACapability(ctx context.Context, cfg runtimeprofile.ProjectProfileConfig) error {
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

func (p *profileAssembly) bindProfileMFA(root string) {
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

func (p *profileAssembly) bindBrowserMFA(root string, views []projectmethods.BrowserPolicy) {
	if len(views) == 0 {
		return
	}
	base := views[0]
	for _, view := range views[1:] {
		if !sameProjectSession(view.Session, base.Session) || view.MFA.Enabled != base.MFA.Enabled || view.MFA.Enabled && !sameProjectMFA(view.MFA, base.MFA) {
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

func (p *profileAssembly) disableProfileBrowser(views []projectmethods.BrowserPolicy, reason string) {
	for _, method := range views {
		p.state(method.Feature, reason)
	}
	p.password, p.google, p.telegram = nil, nil, nil
	if !p.featureReady("reauthentication") {
		p.emailOTP = nil
	}
}

func sameProjectSession(a, b sessionservice.Config) bool {
	return a.FreshAuthSource == nil && b.FreshAuthSource == nil &&
		a.FreshAuthTTL == b.FreshAuthTTL && a.SessionTTL == b.SessionTTL &&
		a.AbsoluteSessionTTL == b.AbsoluteSessionTTL && a.SessionRefreshThreshold == b.SessionRefreshThreshold &&
		a.AdminIdleTimeout == b.AdminIdleTimeout && a.AdminAbsoluteTTL == b.AdminAbsoluteTTL &&
		a.AdminActivityInterval == b.AdminActivityInterval
}

func sameProjectMFA(a, b mfaservice.Config) bool {
	return a.ChallengeTTLSource == nil && b.ChallengeTTLSource == nil && a.BudgetSource == nil && b.BudgetSource == nil &&
		a.Enabled == b.Enabled && a.RecoveryEnabled == b.RecoveryEnabled && a.Issuer == b.Issuer &&
		a.ChallengeTTL == b.ChallengeTTL && a.UserLimitPerMinute == b.UserLimitPerMinute &&
		a.IPLimitPerMinute == b.IPLimitPerMinute && a.GlobalLimitPerMinute == b.GlobalLimitPerMinute
}

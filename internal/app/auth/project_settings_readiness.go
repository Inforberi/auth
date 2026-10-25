package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func (p *ProjectProfile) selectAssessmentPolicy(cfg ProjectProfileConfig) {
	native := cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil
	password, email := false, false
	if native {
		password, email = cfg.Tokens.Native.PasswordEnabled, cfg.Tokens.Native.EmailOTP.Enabled
	}
	p.policy.Policy.Methods = settingsdomain.PublicMethods{
		Password: cfg.BrowserEnabled && cfg.Password != nil || password,
		EmailOTP: cfg.BrowserEnabled && cfg.EmailOTP != nil && cfg.EmailOTP.OTP.Enabled || email,
		Google:   cfg.BrowserEnabled && cfg.Google != nil && cfg.Google.Enabled,
		Telegram: cfg.BrowserEnabled && cfg.Telegram != nil && cfg.Telegram.Enabled,
	}
	p.policy.Policy.PasswordEmailVerification = settingsdomain.VerificationDisabled
	p.policy.Policy.TokenIssuance = settingsdomain.TokenIssuance{SessionExchange: cfg.Tokens != nil && cfg.Tokens.Enabled, Native: native}
}

// Assess checks potential capabilities, never returning a routable candidate profile.
func (h *ProjectHTTP) Assess(ctx context.Context, key projectruntime.Key, origin string) (projectdomain.AuthPolicyReadiness, error) {
	if h == nil || h.source == nil {
		return projectdomain.AuthPolicyReadiness{}, projectdomain.ErrUnavailable
	}
	cfg, err := h.source(ctx, key, origin)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	before, err := h.dependencyVersions(ctx, key)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	profile, err := buildProjectProfile(ctx, key, origin, cfg, h.deps, true)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	after, err := h.dependencyVersions(ctx, key)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	if before != after {
		return projectdomain.AuthPolicyReadiness{}, settingsdomain.ErrPolicyConflict
	}
	for _, feature := range []string{"password", "emailotp", "google", "telegram", "exchange", "native", "verification"} {
		if _, exists := profile.states[feature]; !exists {
			profile.state(feature, "deployment_disabled")
		}
	}
	report := profile.Readiness()
	methods := settingsdomain.PublicMethods{Password: profile.featureReady("password") || profile.featureReady("native_password"), EmailOTP: profile.featureReady("emailotp") || profile.featureReady("native_email"), Google: profile.featureReady("google"), Telegram: profile.featureReady("telegram")}
	runtime := settingsdomain.PolicyRuntime{Configured: true, Methods: methods, Tokens: settingsdomain.TokenIssuance{SessionExchange: profile.featureReady("exchange"), Native: profile.featureReady("native")}, RequireStoredProviders: true, VerificationReady: profile.featureReady("verification"), Dependencies: &after}
	runtime.EmailDeliveryReady = runtime.VerificationReady || methods.EmailOTP || profile.featureReady("recovery")
	result := projectdomain.AuthPolicyReadiness{Runtime: runtime, Features: report.Features, ObservedAt: report.ObservedAt, PolicyVersion: report.PolicyVersion}
	if profile.featureReady("tokens") {
		result.Tokens = tokenDeployment(tokensettings.Config{Enabled: true, Issuer: origin, AccessTTL: cfg.Tokens.Tokens.AccessTTL}, cfg.Tokens.Tokens.Resources, runtime.Tokens.Native, profile.featureReady("introspection"))
	}
	return result, nil
}

func (h *ProjectHTTP) dependencyVersions(ctx context.Context, key projectruntime.Key) (settingsdomain.DependencyVersions, error) {
	var versions settingsdomain.DependencyVersions
	err := h.deps.Registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
		return pool.QueryRow(ctx, `SELECT COALESCE((SELECT version FROM auth.smtp_settings WHERE singleton),0),
		 COALESCE((SELECT version FROM auth.provider_settings WHERE provider='google'),0),
		 COALESCE((SELECT version FROM auth.provider_settings WHERE provider='telegram'),0)`).Scan(&versions.SMTP, &versions.Google, &versions.Telegram)
	})
	return versions, err
}

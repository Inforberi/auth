package profile

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectsettings "github.com/Inforberi/financial-intelligence/internal/auth/project/settings"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	tokensettings "github.com/Inforberi/financial-intelligence/internal/auth/token/settings"
)

func AssessWithBuilder(ctx context.Context, key projectruntime.Key, origin string, cfg ProjectProfileConfig, deps ProjectProfileDependencies, build BuildProfile) (projectdomain.AuthPolicyReadiness, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	before, err := profileDependencyVersions(ctx, key, deps)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	profile, err := build(ctx, key, origin, cfg, deps, true)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	after, err := profileDependencyVersions(ctx, key, deps)
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
		result.Tokens = tokensettings.Deployment(tokensettings.Config{Enabled: true, Issuer: origin, AccessTTL: cfg.Tokens.Tokens.AccessTTL}, cfg.Tokens.Tokens.Resources, runtime.Tokens.Native, profile.featureReady("introspection"))
	}
	return result, nil
}

func profileDependencyVersions(ctx context.Context, key projectruntime.Key, deps ProjectProfileDependencies) (settingsdomain.DependencyVersions, error) {
	return projectsettings.DependencyVersions(ctx, deps.Registry, key)
}

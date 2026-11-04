package profile

import (
	"context"

	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
)

func (p *profileAssembly) buildProfileTokens(ctx context.Context, cfg runtimeprofile.ProjectProfileConfig, redisReady bool) {
	policy := p.policy.Policy
	if cfg.Tokens == nil || !cfg.Tokens.Enabled {
		if policy.TokenIssuance.SessionExchange {
			p.state("exchange", "missing_configuration")
		}
		if policy.TokenIssuance.Native {
			p.state("native", "missing_configuration")
		}
		return
	}
	tokens := *cfg.Tokens
	selected := p.selectProfileNative(cfg, &tokens, redisReady)
	reason := p.assembleProfileTokens(ctx, tokens)
	p.state("tokens", reason)
	if policy.TokenIssuance.SessionExchange {
		p.state("exchange", reason)
	}
	if cfg.Tokens.Introspection != nil {
		p.state("introspection", reason)
	}
	p.finishProfileNative(selected, reason)
	if p.tokens != nil && p.tokens.NativeAvailable() {
		p.state("logout", "")
		if policy.TokenIssuance.Native {
			p.state("refresh", "")
		}
	}
}

func (p *profileAssembly) selectProfileNative(cfg runtimeprofile.ProjectProfileConfig, tokens *projectnative.ProjectTokenConfig, redisReady bool) runtimeprofile.NativeSelection {
	if tokens.Tokens.Native != nil {
		native := *tokens.Tokens.Native
		tokens.Tokens.Native = &native
	}
	selected := cfg.SelectNative(p.policy.Policy, runtimeprofile.NativeReadiness{Redis: redisReady, Delivery: redisReady && p.policy.Policy.TokenIssuance.Native && p.policy.Policy.Methods.EmailOTP && tokens.Native.EmailOTP.Enabled && p.deliveryReady(), Verification: p.featureReady("verification")})
	tokens.Native.PasswordEnabled = selected.Password && selected.PasswordReason == ""
	tokens.Native.EmailOTP.Enabled = selected.Email && selected.EmailReason == ""
	tokens.Native.EmailOTP.ReauthenticationEnabled = false
	if tokens.Native.EmailOTP.Enabled {
		tokens.Native.SMTPAllowedTargets = p.deps.Delivery.AllowedTargets()
	}
	return selected
}

func (p *profileAssembly) assembleProfileTokens(ctx context.Context, cfg projectnative.ProjectTokenConfig) string {
	if cfg.Issuer != p.origin {
		return "origin_mismatch"
	}
	if !profileRedisReady(ctx, p.deps.IssuanceRedis) {
		return "redis_unavailable"
	}
	var err error
	p.tokens, err = projectnative.NewProjectTokens(ctx, p.key, cfg, p.deps.ProjectTokenDependencies)
	if err != nil {
		return "component_unavailable"
	}
	return ""
}

func (p *profileAssembly) finishProfileNative(selected runtimeprofile.NativeSelection, reason string) {
	if !p.policy.Policy.TokenIssuance.Native {
		return
	}
	if reason == "" && (p.tokens == nil || !p.tokens.NativeAvailable()) {
		reason = "missing_configuration"
	}
	if selected.Password {
		failure := selected.PasswordReason
		if reason != "" {
			failure = reason
		}
		p.state("native_password", failure)
	}
	if selected.Email {
		failure := selected.EmailReason
		if reason != "" {
			failure = reason
		}
		p.state("native_email", failure)
	}
	if p.featureReady("native_password") || p.featureReady("native_email") {
		p.state("native", "")
		p.state("native_mfa", "")
	} else {
		if reason == "" {
			reason = "native_primary_unavailable"
		}
		p.state("native", reason)
	}
}

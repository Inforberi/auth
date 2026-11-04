package profile

import (
	"context"

	projectnative "github.com/Inforberi/financial-intelligence/internal/auth/project/token"
)

type profileNativeSelection struct {
	password, email             bool
	passwordReason, emailReason string
}

func (p *ProjectProfile) buildProfileTokens(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
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

func (p *ProjectProfile) selectProfileNative(cfg ProjectProfileConfig, tokens *projectnative.ProjectTokenConfig, redisReady bool) profileNativeSelection {
	policy := p.policy.Policy
	if tokens.Tokens.Native != nil {
		native := *tokens.Tokens.Native
		tokens.Tokens.Native = &native
	}
	selected := profileNativeSelection{password: policy.TokenIssuance.Native && policy.Methods.Password && tokens.Native.PasswordEnabled, email: policy.TokenIssuance.Native && policy.Methods.EmailOTP && tokens.Native.EmailOTP.Enabled}
	if selected.password && !redisReady {
		selected.passwordReason = "redis_unavailable"
	}
	if selected.passwordReason == "" && selected.password && p.needsProfileVerification(cfg) && !p.featureReady("verification") {
		selected.passwordReason = "verification_unavailable"
	}
	if selected.email {
		selected.emailReason = p.mailReason(redisReady)
	}
	tokens.Native.PasswordEnabled = selected.password && selected.passwordReason == ""
	tokens.Native.EmailOTP.Enabled = selected.email && selected.emailReason == ""
	tokens.Native.EmailOTP.ReauthenticationEnabled = false
	if tokens.Native.EmailOTP.Enabled {
		tokens.Native.SMTPAllowedTargets = p.deps.Delivery.AllowedTargets()
	}
	return selected
}

func (p *ProjectProfile) assembleProfileTokens(ctx context.Context, cfg projectnative.ProjectTokenConfig) string {
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

func (p *ProjectProfile) finishProfileNative(selected profileNativeSelection, reason string) {
	if !p.policy.Policy.TokenIssuance.Native {
		return
	}
	if reason == "" && (p.tokens == nil || !p.tokens.NativeAvailable()) {
		reason = "missing_configuration"
	}
	if selected.password {
		failure := selected.passwordReason
		if reason != "" {
			failure = reason
		}
		p.state("native_password", failure)
	}
	if selected.email {
		failure := selected.emailReason
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

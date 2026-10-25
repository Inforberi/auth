package auth

import (
	"context"
	"errors"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (p *ProjectProfile) needsProfileVerification(cfg ProjectProfileConfig) bool {
	policy := p.policy.Policy
	browserPassword := cfg.BrowserEnabled && policy.Methods.Password
	nativePassword := cfg.Tokens != nil && cfg.Tokens.Enabled && cfg.Tokens.Tokens.Native != nil && cfg.Tokens.Native.PasswordEnabled && policy.TokenIssuance.Native && policy.Methods.Password
	return (browserPassword || nativePassword) && policy.PasswordEmailVerification != settingsdomain.VerificationDisabled
}

func (p *ProjectProfile) buildProfileEmail(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
	if cfg.Verification != nil || p.needsProfileVerification(cfg) {
		if cfg.Verification == nil {
			p.state("verification", "missing_configuration")
		} else {
			email := ProjectEmailConfig{Origin: p.origin, VerificationEnabled: true, Verification: *cfg.Verification}
			p.verification = p.profileEmail(ctx, "verification", email, redisReady)
		}
	}
	if cfg.Recovery != nil {
		email := ProjectEmailConfig{Origin: p.origin, RecoveryEnabled: true, Password: *cfg.Recovery}
		p.recovery = p.profileEmail(ctx, "recovery", email, redisReady)
	}
}

func (p *ProjectProfile) profileEmail(ctx context.Context, feature string, cfg ProjectEmailConfig, redisReady bool) *ProjectEmail {
	reason := p.mailReason(redisReady)
	if reason != "" {
		p.state(feature, reason)
		return nil
	}
	email, err := NewProjectEmail(ctx, p.key, cfg, p.deps.Delivery.cfg.SMTPAllowedTargets, ProjectEmailDependencies{ProjectSMTPDependencies: ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis}, Hash: p.deps.Hash})
	if err != nil {
		reason = projectMailFailure(err)
	}
	p.state(feature, reason)
	return email
}

func (p *ProjectProfile) mailReason(redisReady bool) string {
	if !redisReady {
		return "redis_unavailable"
	}
	if !p.deliveryReady() {
		return "delivery_not_running"
	}
	return ""
}

func (p *ProjectProfile) buildProfileOTP(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
	selected := p.policy.Policy.Methods.EmailOTP
	reauthentication := cfg.EmailOTP != nil && cfg.EmailOTP.OTP.ReauthenticationEnabled
	if !selected && !reauthentication {
		return
	}
	if cfg.EmailOTP == nil {
		p.state("emailotp", "missing_configuration")
		return
	}
	primary := selected && cfg.EmailOTP.OTP.Enabled
	if selected && !primary {
		p.state("emailotp", "configuration_disabled")
	}
	if !primary && !reauthentication {
		return
	}
	reason := p.mailReason(redisReady)
	if reason == "" {
		otp := *cfg.EmailOTP
		otp.OTP.Enabled = primary
		var err error
		p.emailOTP, err = NewProjectEmailOTP(ctx, p.key, otp, p.deps.Delivery.cfg.SMTPAllowedTargets, ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
		if err != nil {
			reason = projectMailFailure(err)
		}
	}
	if primary {
		p.state("emailotp", reason)
	}
	if reauthentication {
		p.state("reauthentication", reason)
	}
}

func projectMailFailure(err error) string {
	switch {
	case errors.Is(err, settingsdomain.ErrNotInitialized):
		return "smtp_not_configured"
	case errors.Is(err, settingsdomain.ErrInvalidSMTP):
		return "invalid_smtp_configuration"
	default:
		return "component_unavailable"
	}
}

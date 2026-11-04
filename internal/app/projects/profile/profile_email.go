package profile

import (
	"context"
	"errors"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func (p *profileAssembly) buildProfileEmail(ctx context.Context, cfg runtimeprofile.ProjectProfileConfig, redisReady bool) {
	if cfg.Verification != nil || cfg.NeedsVerification(p.policy.Policy) {
		if cfg.Verification == nil {
			p.state("verification", "missing_configuration")
		} else {
			email := projectaccount.ProjectEmailConfig{Origin: p.origin, VerificationEnabled: true, Verification: *cfg.Verification}
			p.verification = p.profileEmail(ctx, "verification", email, redisReady)
		}
	}
	if cfg.Recovery != nil {
		email := projectaccount.ProjectEmailConfig{Origin: p.origin, RecoveryEnabled: true, Password: *cfg.Recovery}
		p.recovery = p.profileEmail(ctx, "recovery", email, redisReady)
	}
}

func (p *profileAssembly) profileEmail(ctx context.Context, feature string, cfg projectaccount.ProjectEmailConfig, redisReady bool) *projectaccount.ProjectEmail {
	reason := p.mailReason(redisReady)
	if reason != "" {
		p.state(feature, reason)
		return nil
	}
	email, err := projectaccount.NewProjectEmail(ctx, p.key, cfg, p.deps.Delivery.AllowedTargets(), projectaccount.ProjectEmailDependencies{ProjectSMTPDependencies: projectbinding.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis}, Hash: p.deps.Hash})
	if err != nil {
		reason = projectMailFailure(err)
	}
	p.state(feature, reason)
	return email
}

func (p *profileAssembly) mailReason(redisReady bool) string {
	if !redisReady {
		return "redis_unavailable"
	}
	if !p.deliveryReady() {
		return "delivery_not_running"
	}
	return ""
}

func (p *profileAssembly) buildProfileOTP(ctx context.Context, cfg runtimeprofile.ProjectProfileConfig, redisReady bool) {
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
		p.emailOTP, err = projectmethods.NewProjectEmailOTP(ctx, p.key, otp, p.deps.Delivery.AllowedTargets(), projectbinding.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
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

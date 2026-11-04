package profile

import (
	"context"

	projectaccount "github.com/Inforberi/financial-intelligence/internal/auth/project/account"
	runtimeprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
)

func (p *profileAssembly) buildProfileEmailManagement(ctx context.Context, cfg runtimeprofile.ProjectProfileConfig, redisReady bool) {
	if !cfg.BrowserEnabled || cfg.EmailManagement == nil {
		return
	}
	management := *cfg.EmailManagement
	if management.Origin != p.origin {
		if management.Binding.Enabled {
			p.state("email_binding", "origin_mismatch")
			p.state("email_binding_confirmation", "origin_mismatch")
		}
		if management.Change.Enabled {
			p.state("email_change", "origin_mismatch")
			p.state("email_change_protection", "origin_mismatch")
		}
		return
	}
	if management.Binding.Enabled {
		email := projectaccount.ProjectEmailConfig{Origin: p.origin, Binding: management.Binding}
		if cfg.EmailOTP != nil && cfg.EmailOTP.MFA.Enabled {
			p.bindingConfirmation = p.storedProfileEmail(ctx, "email_binding_confirmation", email, redisReady)
		} else {
			p.state("email_binding_confirmation", "mfa_unavailable")
		}
		switch {
		case cfg.EmailOTP == nil || !cfg.EmailOTP.MFA.Enabled:
			p.state("email_binding", "mfa_unavailable")
		case !p.featureReady("reauthentication"):
			p.state("email_binding", "reauthentication_unavailable")
		default:
			p.binding = p.profileEmail(ctx, "email_binding", email, redisReady)
		}
	}
	if management.Change.Enabled {
		email := projectaccount.ProjectEmailConfig{Origin: p.origin, Change: management.Change, Password: management.Password, Verification: management.Verification, FreshAuthTTL: management.FreshAuthTTL}
		p.changeProtection = p.storedProfileEmail(ctx, "email_change_protection", email, redisReady)
		p.change = p.profileEmail(ctx, "email_change", email, redisReady)
	}
}

func (p *profileAssembly) storedProfileEmail(ctx context.Context, feature string, cfg projectaccount.ProjectEmailConfig, redisReady bool) *projectaccount.ProjectEmail {
	if !redisReady {
		p.state(feature, "redis_unavailable")
		return nil
	}
	// Existing-token completion and containment only write SQL/outbox; delivery can recover later.
	email, err := projectaccount.NewStoredProjectEmail(ctx, p.key, cfg, nil, projectaccount.ProjectEmailDependencies{ProjectSMTPDependencies: projectbinding.ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis}, Hash: p.deps.Hash})
	p.feature(feature, err)
	return email
}

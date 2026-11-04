package profile

import (
	"context"

	projectmethods "github.com/Inforberi/financial-intelligence/internal/app/projects/methods"
)

func (p *ProjectProfile) buildProfileMethods(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
	if !cfg.BrowserEnabled {
		return
	}
	// Existing sessions remain manageable when login methods are disabled.
	p.state("sessions", "")
	methods := p.policy.Policy.Methods
	if methods.Password {
		p.buildProfilePassword(ctx, cfg, redisReady)
	}
	p.buildProfileOTP(ctx, cfg, redisReady)
	if methods.Google {
		p.google = p.buildProfileOIDC(ctx, "google", cfg.Google, redisReady)
	}
	if methods.Telegram {
		p.telegram = p.buildProfileOIDC(ctx, "telegram", cfg.Telegram, redisReady)
	}
}

func (p *ProjectProfile) buildProfilePassword(ctx context.Context, cfg ProjectProfileConfig, redisReady bool) {
	switch {
	case cfg.Password == nil:
		p.state("password", "missing_configuration")
	case !redisReady:
		p.state("password", "redis_unavailable")
	case p.needsProfileVerification(cfg) && !p.featureReady("verification"):
		p.state("password", "verification_unavailable")
	default:
		password := *cfg.Password
		// One profile source configures both registration mail and the verification endpoint.
		password.RegistrationVerification = nil
		if cfg.Verification != nil {
			password.RegistrationVerification = &projectmethods.ProjectRegistrationVerification{Origin: p.origin, Config: *cfg.Verification}
		}
		var err error
		p.password, err = projectmethods.NewProjectPassword(ctx, p.key, password, projectmethods.ProjectPasswordDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis, Hash: p.deps.Hash})
		p.feature("password", err)
	}
}

func (p *ProjectProfile) buildProfileOIDC(ctx context.Context, name string, cfg *projectmethods.ProjectOIDCConfig, redisReady bool) *projectmethods.ProjectOIDC {
	switch {
	case cfg == nil:
		p.state(name, "missing_configuration")
		return nil
	case !cfg.Enabled:
		p.state(name, "configuration_disabled")
		return nil
	case cfg.Provider != name || cfg.RedirectURI != p.origin+"/api/v1/auth/"+name+"/callback":
		p.state(name, "origin_or_provider_mismatch")
		return nil
	case !redisReady:
		p.state(name, "redis_unavailable")
		return nil
	}
	service, err := projectmethods.NewProjectOIDC(ctx, p.key, *cfg, projectmethods.ProjectOIDCDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis, Clients: p.deps.OIDCClients})
	if err != nil {
		p.feature(name, err)
		return nil
	}
	err = service.CheckStoredCredentials(ctx)
	if err != nil {
		p.state(name, "provider_credentials_unavailable")
		return nil
	}
	p.state(name, "")
	return service
}

func (p *ProjectProfile) finishProfileRegistration(cfg ProjectProfileConfig) {
	if cfg.BrowserEnabled && p.policy.Policy.Methods.Password && p.policy.Policy.Registration.Enabled {
		reason := ""
		if !p.featureReady("password") {
			reason = "password_unavailable"
		}
		p.state("registration", reason)
	}
	if cfg.BrowserEnabled && p.password != nil && p.featureReady("password") && cfg.Password.TemporaryPassword.Enabled {
		p.state("temporary_password", "")
	}
}

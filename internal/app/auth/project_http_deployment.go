package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/config"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

func openProjectHTTP(ctx context.Context, cfg *config.Config, runtime *projectRuntime, delivery *ProjectDelivery, deps realmDependencies, owned *resources) (*ProjectHTTP, func(), error) {
	c := cfg.Platform.HTTP
	if !c.Enabled {
		return nil, nil, nil
	}
	if runtime == nil {
		return nil, nil, errors.New("project HTTP requires runtime")
	}

	if err := cfg.ValidatePlatform(); err != nil {
		return nil, nil, err
	}
	deployment, err := LoadProjectAuthDeployment(cfg)
	if err != nil {
		return nil, nil, err
	}
	dependencies := ProjectProfileDependencies{ProjectTokenDependencies: ProjectTokenDependencies{Registry: runtime.registry, Reader: runtime.reader, Redis: deps.redis, Hash: deps.hash}, Delivery: delivery}
	if deployment.oidc {
		dependencies.OIDCClients = NewProjectOIDCClients(ctx)
		owned.add(dependencies.OIDCClients.Close)
	}
	if deployment.jwt {
		dependencies.IssuanceRedis, err = NewProjectTokenRedis(deps.redis)
		if err != nil {
			return nil, nil, err
		}
		owned.add(func() {
			if err := dependencies.IssuanceRedis.Close(); err != nil {
				deps.log.Error("project token Redis close failed")
			}
		})
	}
	profile, err := NewProjectHTTP(ProjectHTTPConfig{
		PlatformOrigin: cfg.Platform.Origin,
		Residents:      projecthttp.RuntimeDispatcherConfig{MaxProfiles: c.MaxProfiles, MaxBuilding: c.MaxBuilding, BuildTimeout: c.BuildTimeout, MaxAge: c.MaxAge},
		Capacity:       middleware.CapacityConfig{MaxInFlight: c.MaxInFlight, RequestTimeout: cfg.HTTP.RequestTimeout}, Proxy: cfg.Proxy,
		SessionValidation: &cfg.Session,
	}, dependencies, deployment.Profile, deps.log)
	if err != nil {
		return nil, nil, err
	}
	drain := func() {
		if err := profile.Close(context.WithoutCancel(ctx)); err != nil {
			deps.log.Error("project HTTP drain failed")
		}
	}
	owned.add(drain)
	return profile, drain, nil
}

func projectHostRouter(platformOrigin string, operator http.Handler, project *ProjectHTTP) http.Handler {
	if project == nil {
		return operator
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if "https://"+r.Host == platformOrigin {
			operator.ServeHTTP(w, r)
			return
		}
		project.ServeHTTP(w, r)
	})
}

func projectBrowserDeployment(cfg *config.Config) ProjectProfileSource {
	// Capture only operational values; never retain a platform encryption key or provider secret.
	session, mfa, capacity := cfg.Session, cfg.MFA, cfg.Capacity
	mfa.RecoveryEnabled = false
	verification, recovery := cfg.Account, cfg.Password
	binding, change := cfg.EmailBinding, cfg.EmailChange
	invitations, temporary := cfg.Invitation, cfg.TemporaryPassword
	invitations.Enabled, temporary.Enabled = false, false
	verification.EncryptionKey = ""
	withMail, timeout := cfg.Platform.Delivery.Enabled, cfg.Platform.HTTP.BuildTimeout
	return func(_ context.Context, _ projectruntime.Key, origin string) (ProjectProfileConfig, error) {
		profile := ProjectProfileConfig{BrowserEnabled: true, Timeout: timeout, Password: &ProjectPasswordConfig{Session: session, MFA: mfa, TemporaryPassword: temporary, Capacity: capacity, Timeout: timeout}}
		projectChange := change
		projectChange.ConfirmURL, projectChange.ReportURL, projectChange.RecoveryURL = origin+"/change-email", origin+"/protect-account", origin+"/recover-account"
		projectRecovery := recovery
		projectRecovery.ResetURL = origin + "/reset-password"
		projectInvitations := invitations
		projectInvitations.URL = origin + "/activate"
		profile.EmailManagement = &ProjectEmailConfig{Invitations: projectInvitations, Origin: origin, Binding: binding, Change: projectChange, Verification: verification, Password: projectRecovery, FreshAuthTTL: session.FreshAuthTTL}
		if withMail {
			verify, reset := verification, recovery
			verify.URL, reset.ResetURL = origin+"/verify-email", origin+"/reset-password"
			profile.Verification, profile.Recovery = &verify, &reset
		}
		return profile, nil
	}
}

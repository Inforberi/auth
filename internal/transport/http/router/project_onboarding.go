package router

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	accounthttp "github.com/Inforberi/financial-intelligence/internal/auth/account/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	requestmiddleware "github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type ProjectOnboardingHTTP struct {
	Origin   string
	Setup    *accounthttp.SetupHandler
	Capacity requestmiddleware.CapacityConfig
	Proxy    requestmiddleware.ProxyConfig
	Logger   *zap.Logger
	// Admit checks current catalog authority for this exact project and reservation,
	// not a cached preparation receipt. It must honor the request deadline.
	Admit func(context.Context) (bool, error)
}

func NewProjectOnboarding(profile ProjectOnboardingHTTP) (http.Handler, error) {
	if !projectdomain.ValidOrigin(profile.Origin) || profile.Setup == nil || profile.Admit == nil {
		return nil, errors.New("incomplete project onboarding HTTP profile")
	}
	if err := profile.Capacity.Validate(); err != nil {
		return nil, err
	}
	if err := profile.Proxy.Validate(); err != nil {
		return nil, err
	}
	origin, err := url.Parse(profile.Origin)
	if err != nil {
		return nil, err
	}
	cfg := &config.Config{HTTP: profile.Capacity, Proxy: profile.Proxy}
	r := baseRouter(Handlers{Config: cfg, Logger: profile.Logger})
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if r.TLS == nil || r.Host != origin.Host {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	guard := requestmiddleware.BrowserProtection(requestmiddleware.OriginConfig{
		AllowedOrigins: []string{profile.Origin},
	})
	protected := r.With(guard, projectOnboardingAdmission(profile.Admit))
	// Explicit allowlist: adding a route to the ordinary router must not expose it here.
	protected.Post("/api/v1/setup/start", profile.Setup.Start)
	protected.Post("/api/v1/setup/complete", profile.Setup.Complete)
	return r, nil
}

func projectOnboardingAdmission(check func(context.Context) (bool, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, err := check(r.Context())
			if err != nil || r.Context().Err() != nil {
				httpx.Error(w, http.StatusServiceUnavailable, "temporarily_unavailable", "temporarily unavailable")
				return
			}
			if !allowed {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

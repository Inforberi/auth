package auth

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type ProjectHTTPConfig struct {
	PlatformOrigin string
	Residents      projecthttp.RuntimeDispatcherConfig
	Capacity       middleware.CapacityConfig
	Proxy          middleware.ProxyConfig
	// Also keeps existing browser sessions manageable when all login methods are disabled.
	SessionValidation *sessionservice.Config
}

type ProjectProfileSource func(context.Context, projectruntime.Key, string) (ProjectProfileConfig, error)

type ProjectHTTP struct {
	http.Handler
	dispatcher *projecthttp.RuntimeDispatcher
	source     ProjectProfileSource
	deps       ProjectProfileDependencies
}

func NewProjectHTTP(cfg ProjectHTTPConfig, deps ProjectProfileDependencies, source ProjectProfileSource, log *zap.Logger) (*ProjectHTTP, error) {
	if source == nil || deps.Reader == nil || deps.Registry == nil {
		return nil, projectdomain.ErrUnavailable
	}
	if log == nil {
		log = zap.NewNop()
	}
	if cfg.SessionValidation != nil {
		copy := *cfg.SessionValidation
		cfg.SessionValidation = &copy
	}
	dispatcher, err := projecthttp.NewRuntimeDispatcher(cfg.Residents, func(ctx context.Context, key projectruntime.Key, origin string) (projecthttp.RuntimeRoutes, error) {
		features, err := source(ctx, key, origin)
		if err != nil {
			return nil, err
		}
		profile, err := BuildProjectProfile(ctx, key, origin, features, deps)
		if err != nil {
			return nil, err
		}
		return profile.httpRoutes(cfg.SessionValidation, log)
	})
	if err != nil {
		return nil, err
	}
	handler, err := router.NewProjectRuntime(cfg.PlatformOrigin, deps.Reader, dispatcher, cfg.Capacity, cfg.Proxy, log)
	if err != nil {
		return nil, err
	}
	return &ProjectHTTP{Handler: handler, dispatcher: dispatcher, source: source, deps: deps}, nil
}

func (h *ProjectHTTP) Close(ctx context.Context) error { return h.dispatcher.Close(ctx) }

type projectHTTPRoutes struct {
	profile *ProjectProfile
	http.Handler
}

func (h *projectHTTPRoutes) CheckCurrent(ctx context.Context) error {
	selected, ok := projecthttp.RuntimeFromContext(ctx)
	if !ok || selected.Key() != h.profile.key || selected.Origin() != h.profile.origin {
		return projectdomain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Boundary already resolved this exact key; retain SQL policy and final catalog guards.
	return h.profile.checkPolicyCurrent(ctx)
}

func (h *projectHTTPRoutes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	selected, ok := projecthttp.RuntimeFromContext(r.Context())
	if !ok || selected.Key() != h.profile.key || selected.Origin() != h.profile.origin {
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
		return
	}
	h.Handler.ServeHTTP(w, r)
}

package router

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/Inforberi/financial-intelligence/internal/config"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/platform/project/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type ProjectRoute struct {
	Method, Path, Protection string
	Handler                  http.Handler
}

type ProjectRouteProtection struct {
	SessionNoRefresh func(http.Handler) http.Handler
	Native           func(http.Handler) http.Handler
}

func NewProjectRoutes(origin string, routes []ProjectRoute, protection ProjectRouteProtection) (http.Handler, error) {
	if !projectdomain.ValidOrigin(origin) {
		return nil, projectdomain.ErrInvalidProject
	}
	r := chi.NewRouter()
	browser := middleware.BrowserProtection(middleware.OriginConfig{AllowedOrigins: []string{origin}})
	seen := make(map[string]bool)
	for _, route := range routes {
		id := route.Method + " " + route.Path
		if route.Handler == nil || seen[id] {
			return nil, errors.New("invalid project route binding")
		}
		seen[id] = true
		handler := route.Handler
		switch route.Protection {
		case "browser", "callback":
			handler = browser(handler)
		case "session_no_refresh":
			if protection.SessionNoRefresh == nil {
				return nil, errors.New("missing project session protection")
			}
			handler = browser(protection.SessionNoRefresh(handler))
		case "native":
			if protection.Native == nil {
				return nil, errors.New("missing project native protection")
			}
			handler = protection.Native(handler)
		case "service", "public_keys": // Existing service handler owns its Basic/transport checks.
		default:
			return nil, errors.New("unknown project route protection")
		}
		r.Method(route.Method, route.Path, handler)
	}
	return r, nil
}

// NewProjectRuntime owns the process middleware once, outside all resident profiles.
func NewProjectRuntime(platformOrigin string, resolver projecthttp.RuntimeResolver, dispatcher http.Handler, capacity middleware.CapacityConfig, proxy middleware.ProxyConfig, log *zap.Logger) (http.Handler, error) {
	if err := capacity.Validate(); err != nil {
		return nil, err
	}
	if err := proxy.Validate(); err != nil {
		return nil, err
	}
	boundary, err := projecthttp.NewRuntimeBoundary(platformOrigin, resolver, dispatcher)
	if err != nil {
		return nil, err
	}
	r := baseRouter(Handlers{Config: &config.Config{HTTP: capacity, Proxy: proxy}, Logger: log})
	r.Mount("/", boundary)
	return r, nil
}

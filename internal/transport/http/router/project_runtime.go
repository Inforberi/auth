package router

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
)

type ProjectRoute struct {
	Method, Path, Protection string
	Handler                  http.Handler
}

type ProjectRouteProtection struct {
	Browser          middleware.OriginConfig
	Session          func(http.Handler) http.Handler
	SessionNoRefresh func(http.Handler) http.Handler
	SessionLogout    func(http.Handler) http.Handler
	Native           func(http.Handler) http.Handler
}

func NewProjectRoutes(origin string, routes []ProjectRoute, protection ProjectRouteProtection) (http.Handler, error) {
	if !projectdomain.ValidOrigin(origin) {
		return nil, projectdomain.ErrInvalidProject
	}
	r := chi.NewRouter()
	if len(protection.Browser.AllowedOrigins) == 0 {
		protection.Browser.AllowedOrigins = []string{origin}
	}
	browser := middleware.BrowserProtection(protection.Browser)
	seen := make(map[string]bool)
	preflight := make(map[string]map[string]bool)
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
		case "session", "session_no_refresh", "session_logout":
			protect := protection.SessionNoRefresh
			switch route.Protection {
			case "session":
				protect = protection.Session
			case "session_logout":
				protect = protection.SessionLogout
			}
			if protect == nil {
				return nil, errors.New("missing project session protection")
			}
			handler = browser(protect(handler))
		case "native":
			if protection.Native == nil {
				return nil, errors.New("missing project native protection")
			}
			handler = protection.Native(handler)
		case "service", "public_keys": // Existing service handler owns its Basic/transport checks.
		default:
			return nil, errors.New("unknown project route protection")
		}
		switch route.Protection {
		case "browser", "callback", "session", "session_no_refresh", "session_logout":
			if preflight[route.Path] == nil {
				preflight[route.Path] = make(map[string]bool)
			}
			preflight[route.Path][route.Method] = true
		}
		r.Method(route.Method, route.Path, handler)
	}
	for path, methods := range preflight {
		cors := browser(http.NotFoundHandler())
		r.Options(path, func(w http.ResponseWriter, req *http.Request) {
			if !methods[req.Header.Get("Access-Control-Request-Method")] {
				http.NotFound(w, req)
				return
			}
			cors.ServeHTTP(w, req)
		})
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

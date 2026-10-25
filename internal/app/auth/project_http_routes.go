package auth

import (
	"errors"
	"net/http"

	"go.uber.org/zap"

	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func (p *ProjectProfile) httpRoutes(fallback *sessionservice.Config, log *zap.Logger) (*projectHTTPRoutes, error) {
	if p.observedAt.IsZero() || !p.key.Valid() {
		return nil, errors.New("unbuilt project HTTP profile")
	}
	handlers := p.browserHandlers(log)
	native := p.tokenHandlers(handlers, log)
	var protection router.ProjectRouteProtection
	if native != nil {
		protection.Native = native.Protect
	}
	plan := p.RoutePlan()
	routes := make([]router.ProjectRoute, 0, len(plan))
	for _, route := range plan {
		handler := handlers[route.Path]
		if handler == nil {
			return nil, errors.New("missing project HTTP scenario")
		}
		if route.Protection == "session_no_refresh" && protection.SessionNoRefresh == nil {
			cfg, err := p.httpSessionConfig(fallback)
			if err != nil {
				return nil, err
			}
			protection.SessionNoRefresh = sessionhttp.New(&projectHTTPSessions{profile: p, cfg: cfg}, log).NoRefreshAuth
		}
		routes = append(routes, router.ProjectRoute{Method: route.Method, Path: route.Path, Protection: route.Protection, Handler: http.HandlerFunc(handler)})
	}
	handler, err := router.NewProjectRoutes(p.origin, routes, protection)
	if err != nil {
		return nil, err
	}
	return &projectHTTPRoutes{profile: p, Handler: handler}, nil
}

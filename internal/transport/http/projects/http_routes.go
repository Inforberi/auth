package browser

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"go.uber.org/zap"

	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func BindRoutes(profile *projectprofile.ProjectProfile, fallback *sessionservice.Config, log *zap.Logger) (*projectHTTPRoutes, error) {
	endpoints, err := profile.Endpoints()
	if err != nil {
		return nil, err
	}
	p := &binding{Endpoints: endpoints}

	handlers := p.browserHandlers(log)
	if err := p.emailMFAHandlers(handlers, log); err != nil {
		return nil, err
	}
	p.telegramMFAHandlers(handlers, log)
	native := p.tokenHandlers(handlers, log)
	var protection router.ProjectRouteProtection
	if p.Frontend != nil {
		protection.Browser.PolicySource = func(ctx context.Context) (middleware.OriginConfig, error) {
			frontend, err := p.Frontend(ctx)
			return middleware.OriginConfig{AllowedOrigins: strings.Split(frontend.Origins, ","), CORSEnabled: frontend.CORSEnabled}, err
		}
	}
	if native != nil {
		protection.Native = native.Protect
	}
	if p.Available("sessions") || p.Available("exchange") || p.Available("reauthentication") {
		sessions, err := p.Sessions(fallback)
		if err != nil {
			return nil, err
		}
		guard := sessionhttp.New(sessions, log)
		protection.Session, protection.SessionNoRefresh, protection.SessionLogout = guard.Auth, guard.NoRefreshAuth, guard.LogoutAuth
		if p.Available("sessions") {
			bindSessionHandlers(sessions, handlers, log)
		}
	}
	plan := p.RoutePlan()
	routes := make([]router.ProjectRoute, 0, len(plan))
	for _, route := range plan {
		handler := handlers[route.Method+" "+route.Path]
		if handler == nil {
			handler = handlers[route.Path]
		}
		if handler == nil {
			return nil, errors.New("missing project HTTP scenario")
		}
		routes = append(routes, router.ProjectRoute{Method: route.Method, Path: route.Path, Protection: route.Protection, Handler: http.HandlerFunc(handler)})
	}
	handler, err := router.NewProjectRoutes(p.Origin, routes, protection)
	if err != nil {
		return nil, err
	}
	return &projectHTTPRoutes{profile: p, Handler: handler}, nil
}

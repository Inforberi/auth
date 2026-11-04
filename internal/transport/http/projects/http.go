package browser

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type ProjectHTTP struct {
	http.Handler
	dispatcher *projecthttp.RuntimeDispatcher
	source     projectprofile.ProjectProfileSource
	deps       projectprofile.ProjectProfileDependencies
}

func NewProjectHTTP(cfg projectprofile.ProjectHTTPConfig, deps projectprofile.ProjectProfileDependencies, source projectprofile.ProjectProfileSource, log *zap.Logger) (*ProjectHTTP, error) {
	if source == nil || deps.Reader == nil || deps.Registry == nil {
		return nil, projectdomain.ErrUnavailable
	}
	if deps.SMTPTests == nil {
		deps.SMTPTests = settingssmtp.NewSMTPTestGate()
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
		profile, err := projectprofile.BuildProjectProfile(ctx, key, origin, features, deps)
		if err != nil {
			return nil, err
		}
		return BindRoutes(profile, cfg.SessionValidation, log)
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

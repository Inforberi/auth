package browser

import (
	"context"
	"net/http"

	"go.uber.org/zap"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

type ProjectHTTP struct {
	http.Handler
	dispatcher *projecthttp.RuntimeDispatcher
	factory    projectprofile.Factory
}

func NewProjectHTTP(cfg projectprofile.ProjectHTTPConfig, reader projecthttp.RuntimeResolver, factory projectprofile.Factory, log *zap.Logger) (*ProjectHTTP, error) {
	if factory == nil || reader == nil {
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
		profile, err := factory.Build(ctx, key, origin)
		if err != nil {
			return nil, err
		}
		return BindRoutes(profile, cfg.SessionValidation, log)
	})
	if err != nil {
		return nil, err
	}
	handler, err := router.NewProjectRuntime(cfg.PlatformOrigin, reader, dispatcher, cfg.Capacity, cfg.Proxy, log)
	if err != nil {
		return nil, err
	}
	return &ProjectHTTP{Handler: handler, dispatcher: dispatcher, factory: factory}, nil
}
func (h *ProjectHTTP) Close(ctx context.Context) error { return h.dispatcher.Close(ctx) }

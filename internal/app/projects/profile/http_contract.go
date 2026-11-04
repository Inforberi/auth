package profile

import (
	"context"
	"net/http"
	"time"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/middleware"
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

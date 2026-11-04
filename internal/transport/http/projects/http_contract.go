package browser

import (
	"context"
	"net/http"
	"time"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projecthttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type projectHTTPRoutes struct {
	profile *binding
	http.Handler
}

func (h *projectHTTPRoutes) CheckCurrent(ctx context.Context) error {
	selected, ok := projecthttp.RuntimeFromContext(ctx)
	if !ok || selected.Key() != h.profile.Key || selected.Origin() != h.profile.Origin {
		return projectdomain.ErrConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Boundary already resolved this exact key; retain SQL policy and final catalog guards.
	return h.profile.CheckPolicyCurrent(ctx)
}

func (h *projectHTTPRoutes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	selected, ok := projecthttp.RuntimeFromContext(r.Context())
	if !ok || selected.Key() != h.profile.Key || selected.Origin() != h.profile.Origin {
		httpx.Error(w, 503, "temporarily_unavailable", "temporarily unavailable")
		return
	}
	h.Handler.ServeHTTP(w, r)
}

package browser

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
)

// Assess checks potential capabilities, never returning a routable candidate profile.
func (h *ProjectHTTP) Assess(ctx context.Context, key projectruntime.Key, origin string) (projectdomain.AuthPolicyReadiness, error) {
	if h == nil || h.factory == nil {
		return projectdomain.AuthPolicyReadiness{}, projectdomain.ErrUnavailable
	}
	return h.factory.Assess(ctx, key, origin)
}

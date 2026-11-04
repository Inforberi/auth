package browser

import (
	"context"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

// Assess checks potential capabilities, never returning a routable candidate profile.
func (h *ProjectHTTP) Assess(ctx context.Context, key projectruntime.Key, origin string) (projectdomain.AuthPolicyReadiness, error) {
	if h == nil || h.source == nil {
		return projectdomain.AuthPolicyReadiness{}, projectdomain.ErrUnavailable
	}
	cfg, err := h.source(ctx, key, origin)
	if err != nil {
		return projectdomain.AuthPolicyReadiness{}, err
	}
	return projectprofile.AssessProjectProfile(ctx, key, origin, cfg, h.deps)
}

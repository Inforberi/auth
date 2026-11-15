package browser

import (
	"context"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
)

func (h *ProjectHTTP) SettingsProfile(ctx context.Context, key projectruntime.Key, origin string) (projectprofile.Endpoints, error) {
	if h == nil || h.factory == nil {
		return projectprofile.Endpoints{}, domain.ErrUnavailable
	}
	profile, err := h.factory.Build(ctx, key, origin)
	if err != nil {
		return projectprofile.Endpoints{}, err
	}
	return profile.Endpoints()
}

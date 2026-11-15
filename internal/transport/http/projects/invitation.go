package browser

import (
	"context"

	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	provisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
)

func (h *ProjectHTTP) PrepareInvitation(ctx context.Context, key projectruntime.Key, origin string, actor accountdomain.UserID, email string) (provisioning.ProvisionCommand, error) {
	if h == nil || h.factory == nil {
		return provisioning.ProvisionCommand{}, accountdomain.ErrProvisionDisabled
	}
	profile, err := h.factory.Build(ctx, key, origin)
	if err != nil {
		return provisioning.ProvisionCommand{}, err
	}
	endpoints, err := profile.Endpoints()
	if err != nil {
		return provisioning.ProvisionCommand{}, err
	}
	if endpoints.Provisioning == nil || endpoints.Activation == nil || endpoints.Password == nil {
		return provisioning.ProvisionCommand{}, accountdomain.ErrProvisionDisabled
	}
	return endpoints.Provisioning.PreparePlatformInvitation(ctx, actor, email)
}

func (h *ProjectHTTP) PrepareTemporaryPassword(ctx context.Context, key projectruntime.Key, origin string, actor accountdomain.UserID, email string) (passwordprovisioning.PreparedTemporaryPassword, error) {
	password, err := h.temporaryPasswordProfile(ctx, key, origin)
	if err != nil {
		return passwordprovisioning.PreparedTemporaryPassword{}, err
	}
	return password.PreparePlatformTemporary(ctx, actor, email)
}

func (h *ProjectHTTP) PrepareTemporaryReissue(ctx context.Context, key projectruntime.Key, origin string, actor accountdomain.UserID) (passwordprovisioning.PreparedTemporaryPassword, error) {
	password, err := h.temporaryPasswordProfile(ctx, key, origin)
	if err != nil {
		return passwordprovisioning.PreparedTemporaryPassword{}, err
	}
	return password.PreparePlatformReissue(ctx, actor)
}

func (h *ProjectHTTP) temporaryPasswordProfile(ctx context.Context, key projectruntime.Key, origin string) (*projectmethods.ProjectPassword, error) {
	if h == nil || h.factory == nil {
		return nil, passworddomain.ErrTemporaryPasswordDisabled
	}
	profile, err := h.factory.Build(ctx, key, origin)
	if err != nil {
		return nil, err
	}
	endpoints, err := profile.Endpoints()
	if err != nil {
		return nil, err
	}
	if endpoints.Password == nil || !endpoints.Available("temporary_password_admin") {
		return nil, passworddomain.ErrTemporaryPasswordDisabled
	}
	return endpoints.Password, nil
}

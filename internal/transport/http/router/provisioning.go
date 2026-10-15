package router

import "github.com/go-chi/chi/v5"

func provisioningRoutes(r chi.Router, h Handlers) {
	if h.Config == nil || !h.Config.MFA.Enabled || h.Middleware == nil {
		return
	}
	admin := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	if h.Provisioning != nil && h.Config.Invitation.Enabled {
		admin.Post("/admin/users", h.Provisioning.Provision)
		admin.Post("/admin/users/{id}/invitation", h.Provisioning.ReissueInvitation)
	}
	if h.TemporaryAdmin != nil && h.Config.TemporaryPassword.Enabled {
		admin.Post("/admin/users/temporary-password", h.TemporaryAdmin.Provision)
		admin.Post("/admin/users/{id}/temporary-password", h.TemporaryAdmin.Reissue)
	}
}

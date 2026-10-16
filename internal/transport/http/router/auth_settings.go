package router

import "github.com/go-chi/chi/v5"

func authSettingsRoutes(r chi.Router, h Handlers) {
	if h.AuthSettings == nil || h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	protected.Get("/admin/auth/settings", h.AuthSettings.Read)
	if h.Config != nil && h.Config.MFA.Enabled {
		protected.Post("/admin/auth/settings", h.AuthSettings.Update)
	}
}

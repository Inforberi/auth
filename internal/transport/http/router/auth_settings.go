package router

import "github.com/go-chi/chi/v5"

func authSettingsRoutes(r chi.Router, h Handlers) {
	if h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	if h.AuthSettings != nil {
		protected.Get("/admin/auth/settings", h.AuthSettings.Read)
		if h.Config != nil && h.Config.MFA.Enabled {
			protected.Post("/admin/auth/settings", h.AuthSettings.Update)
		}
	}
	if h.SMTPSettings != nil {
		protected.Get("/admin/auth/settings/smtp", h.SMTPSettings.Read)
		if h.Config != nil && h.Config.MFA.Enabled {
			protected.Post("/admin/auth/settings/smtp", h.SMTPSettings.Update)
			protected.Post("/admin/auth/settings/smtp/test", h.SMTPSettings.TestConnection)
		}
	}
}

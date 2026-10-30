package router

import "github.com/go-chi/chi/v5"

func operatorMFASettingsRoutes(r chi.Router, h Handlers) {
	if h.MFASettings == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	if h.ProjectCapacity != nil {
		protected = protected.With(h.ProjectCapacity)
	}
	protected.Get("/platform/settings/mfa", h.MFASettings.Read)
	protected.Post("/platform/settings/mfa", h.MFASettings.Update)
}

func authSettingsRoutes(r chi.Router, h Handlers) {
	if h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	if h.MFASettings != nil {
		protected.Get("/admin/auth/settings/mfa", h.MFASettings.Read)
		protected.Post("/admin/auth/settings/mfa", h.MFASettings.Update)
	}
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
	if h.ProviderSettings != nil {
		protected.Get("/admin/auth/settings/providers/{provider}", h.ProviderSettings.Read)
		if h.Config != nil && h.Config.MFA.Enabled {
			protected.Post("/admin/auth/settings/providers/{provider}", h.ProviderSettings.Update)
		}
	}
	if h.RetentionSettings != nil {
		protected.Get("/admin/auth/settings/retention", h.RetentionSettings.Read)
		if h.Config != nil && h.Config.MFA.Enabled {
			protected.Post("/admin/auth/settings/retention", h.RetentionSettings.Update)
		}
	}
}

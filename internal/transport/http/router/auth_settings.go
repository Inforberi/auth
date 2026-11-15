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
	protected.Get("/platform/settings/mfa", h.MFASettings.ReadPlatform)
	protected.Post("/platform/settings/mfa", h.MFASettings.UpdatePlatform)
}

func authSettingsRoutes(r chi.Router, h Handlers) {
	if h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	writable := h.Config != nil && h.Config.MFA.Enabled
	if h.MFASettings != nil {
		protected.Get("/admin/auth/settings/mfa", h.MFASettings.Read)
		protected.Post("/admin/auth/settings/mfa", h.MFASettings.Update)
	}
	if h.AuthSettings != nil {
		protected.Get("/admin/auth/settings", h.AuthSettings.Read)
		if writable {
			protected.Post("/admin/auth/settings", h.AuthSettings.Update)
		}
	}
	if h.SMTPSettings != nil {
		protected.Get("/admin/auth/settings/smtp", h.SMTPSettings.Read)
		if writable {
			protected.Post("/admin/auth/settings/smtp", h.SMTPSettings.Update)
			protected.Post("/admin/auth/settings/smtp/test", h.SMTPSettings.TestConnection)
		}
	}
	if h.ProviderSettings != nil {
		protected.Get("/admin/auth/settings/providers/{provider}", h.ProviderSettings.Read)
		if writable {
			protected.Post("/admin/auth/settings/providers/{provider}", h.ProviderSettings.Update)
		}
	}
	if h.EmailOTPPolicy != nil {
		protected.Get("/admin/auth/settings/email-otp", h.EmailOTPPolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/email-otp", h.EmailOTPPolicy.Update)
		}
	}
	if h.BrowserSessionPolicy != nil {
		protected.Get("/admin/auth/settings/sessions", h.BrowserSessionPolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/sessions", h.BrowserSessionPolicy.Update)
		}
	}
	if h.RetentionSettings != nil {
		protected.Get("/admin/auth/settings/retention", h.RetentionSettings.Read)
		if writable {
			protected.Post("/admin/auth/settings/retention", h.RetentionSettings.Update)
		}
	}
}

func timingSettingsRoutes(r chi.Router, h Handlers) {
	if h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	writable := h.Config != nil && h.Config.MFA.Enabled
	if h.LinkLifetimePolicy != nil {
		protected.Get("/admin/auth/settings/link-lifetimes", h.LinkLifetimePolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/link-lifetimes", h.LinkLifetimePolicy.Update)
		}
	}
	if h.CredentialLifetimePolicy != nil {
		protected.Get("/admin/auth/settings/credential-lifetimes", h.CredentialLifetimePolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/credential-lifetimes", h.CredentialLifetimePolicy.Update)
		}
	}
}

func runtimeSettingsRoutes(r chi.Router, h Handlers) {
	if h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	writable := h.Config != nil && h.Config.MFA.Enabled
	if h.LoginBudgetPolicy != nil {
		protected.Get("/admin/auth/settings/login-budgets", h.LoginBudgetPolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/login-budgets", h.LoginBudgetPolicy.Update)
		}
	}
	if h.OperationBudgetsPolicy != nil {
		protected.Get("/admin/auth/settings/operation-budgets", h.OperationBudgetsPolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/operation-budgets", h.OperationBudgetsPolicy.Update)
		}
	}
	if h.FrontendPolicy != nil {
		protected.Get("/admin/auth/settings/frontend", h.FrontendPolicy.Read)
		if writable {
			protected.Post("/admin/auth/settings/frontend", h.FrontendPolicy.Update)
		}
	}
}

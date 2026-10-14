package router

import "github.com/go-chi/chi/v5"

func emailBindingRoutes(r chi.Router, h Handlers) {
	if h.EmailBinding == nil || h.Config == nil || !h.Config.EmailBinding.Enabled || !h.Config.MFA.Enabled || !h.Config.EmailOTP.ReauthenticationEnabled {
		return
	}
	owner := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	owner.Post("/admin/users/{id}/email-binding", h.EmailBinding.Request)
	owner.Post("/auth/email/binding/confirm", h.EmailBinding.Confirm)
}

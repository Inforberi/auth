package router

import "github.com/go-chi/chi/v5"

func userLifecycleRoutes(r chi.Router, h Handlers) {
	if h.UserLifecycle == nil || h.Middleware == nil || h.Config == nil || !h.Config.MFA.Enabled {
		return
	}
	admin := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	admin.Post("/admin/users/{id}/status", h.UserLifecycle.ChangeStatus)
	admin.Delete("/admin/users/{id}", h.UserLifecycle.Delete)
}

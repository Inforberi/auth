package router

import "github.com/go-chi/chi/v5"

func userDirectoryRoutes(r chi.Router, h Handlers) {
	if h.UserDirectory == nil || h.Middleware == nil {
		return
	}
	reader := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	reader.Get("/admin/users", h.UserDirectory.List)
	reader.Get("/admin/users/{id}", h.UserDirectory.Read)
}

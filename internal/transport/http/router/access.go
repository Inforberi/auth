package router

import "github.com/go-chi/chi/v5"

func accessRoutes(r chi.Router, h Handlers) {
	if h.Access == nil || h.Middleware == nil {
		return
	}
	protected := r.With(browserProtection(h), h.Middleware.NoRefreshAuth)
	protected.Get("/auth/access", h.Access.MyAccess)
	protected.Get("/admin/permissions", h.Access.PermissionCatalog)
	protected.Get("/admin/roles", h.Access.ListRoles)
	protected.Get("/admin/roles/{id}", h.Access.ReadRole)
	protected.Get("/admin/users/{id}/access", h.Access.UserAssignments)
	// Reads remain useful with MFA disabled; every mutation still enforces fresh MFA in SQL.
	if h.Config == nil || !h.Config.MFA.Enabled {
		return
	}
	protected.Post("/admin/roles", h.Access.CreateRole)
	protected.Post("/admin/roles/{id}", h.Access.UpdateRole)
	protected.Post("/admin/users/{id}/roles/{roleId}", h.Access.GrantRole)
	protected.Delete("/admin/users/{id}/roles/{roleId}", h.Access.RevokeRole)
}

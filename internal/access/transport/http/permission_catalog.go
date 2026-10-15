package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PermissionCatalogResponse struct {
	Permissions []settings.Permission `json:"permissions"`
} // @name access_http.PermissionCatalogResponse

// @Summary Read the project's permission catalog
// @Description Requires current access.roles.manage or access.assignments.manage. Returns declared keys, not an ability to create arbitrary permissions through HTTP.
// @Tags Admin Access
// @Produce json
// @Success 200 {object} PermissionCatalogResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/permissions [get]
func (h *Handler) PermissionCatalog(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	permissions, err := h.service.PermissionCatalog(r.Context(), actor)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, PermissionCatalogResponse{Permissions: permissions})
}

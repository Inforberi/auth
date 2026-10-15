package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a role and its permissions
// @Description Requires current access.roles.manage or access.assignments.manage. Includes version for a subsequent explicit edit or assignment. Reads do not renew session or authentication freshness.
// @Tags Admin Access
// @Produce json
// @Param id path string true "Role UUID"
// @Success 200 {object} RoleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/roles/{id} [get]
func (h *Handler) ReadRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := principal(w, r)
	if !ok {
		return
	}
	role, err := h.service.ReadManagedRole(r.Context(), actor, domain.RoleID(chi.URLParam(r, "id")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, roleResponse(role))
}

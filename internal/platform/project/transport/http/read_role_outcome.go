package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read the caller's project role operation
// @Description Requires current platform.projects.read and fresh password/MFA. Exact project/operation/caller scope. Foreign project, unknown UUID and another caller's operation share not-found. committed=false means unknown, not rollback. This GET reads catalog evidence only and never opens a project connection. An existing result remains readable after write permission revoke or project suspension.
// @Tags Platform Roles
// @Produce json
// @Param Origin header string false "If supplied, exact platform HTTPS origin"
// @Param id path string true "Project UUID"
// @Param operationId path string true "Operation UUID"
// @Success 200 {object} RoleOutcomeResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/role-operations/{operationId} [get]
func (h *RoleHandler) Read(w http.ResponseWriter, r *http.Request) {
	actor, ok := operationActor(w, r)
	if !ok || !emptyRequestBody(w, r) {
		return
	}
	result, err := h.service.ReadRoleOutcome(r.Context(), actor, domain.ID(chi.URLParam(r, "id")), domain.ID(chi.URLParam(r, "operationId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, roleOutcomeResponse(result))
}

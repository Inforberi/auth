package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Recover the caller's project role operation result
// @Description Empty body. Requires current platform.projects.read and fresh password/MFA before recovery and before disclosure. Checks project/operation/caller scope before borrowing any project connection. Reads the original project receipt on the exact trusted runtime; records completion evidence only, never retries role mutation or creates an admission. Missing receipt remains unknown. Cold suspended/stale target may be unavailable; there is no fallback to another DB.
// @Tags Platform Roles
// @Produce json
// @Param Origin header string true "Exact platform HTTPS origin"
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
// @Router /api/v1/platform/projects/{id}/role-operations/{operationId}/reconcile [post]
func (h *RoleHandler) Reconcile(w http.ResponseWriter, r *http.Request) {
	actor, ok := operationActor(w, r)
	if !ok || !emptyRequestBody(w, r) {
		return
	}
	result, err := h.service.ReconcileRoleOutcome(r.Context(), actor, domain.ID(chi.URLParam(r, "id")), domain.ID(chi.URLParam(r, "operationId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, roleOutcomeResponse(result))
}

package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

// @Summary Read a current project role with permissions
// @Description Requires current platform.project_access.manage and fresh password/MFA before read and before disclosure. Exact enabled/ready project binding, version/generation and role UUID. Role and permissions come from one read-only repeatable-read project snapshot. No project identity impersonation, mutations, admissions or session renewal. A foreign or unknown role UUID is not found.
// @Tags Platform Roles
// @Produce json
// @Param id path string true "Project UUID"
// @Param roleId path string true "Role UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Success 200 {object} PlatformRoleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/roles/{roleId} [get]
func (h *RoleHandler) ReadRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := requestActor(w, r)
	if !ok || !emptyRoleBody(w, r) {
		return
	}
	query, ok := roleDirectoryQuery(w, r, false)
	if !ok {
		return
	}
	role, err := h.service.ReadProjectRole(r.Context(), actor, query.Target, accessdomain.RoleID(chi.URLParam(r, "roleId")))
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, platformRoleResponse(role))
}

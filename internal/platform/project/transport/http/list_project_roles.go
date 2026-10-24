package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type PlatformRolePageResponse struct {
	Roles        []PlatformRoleSummary `json:"roles"`
	NextAfterKey string                `json:"nextAfterKey"`
} // @name project_http.PlatformRolePageResponse

// @Summary List current project roles from the platform
// @Description Requires current platform.project_access.manage and fresh password/MFA, checked before the project read and again before disclosure. Exact enabled/ready target and version/generation; read-only project snapshot. Exclusive key pagination, no total count, offset or per-row permission queries. Includes system-role metadata; assignments to system roles remain forbidden. Does not renew sessions or create operation receipts. Get permissions from the role detail endpoint.
// @Tags Platform Roles
// @Produce json
// @Param id path string true "Project UUID"
// @Param expectedVersion query int true "Current project version"
// @Param expectedGeneration query int true "Current project generation"
// @Param afterKey query string false "Exclusive nextAfterKey from previous page"
// @Param limit query int false "Page size 1..100, default 50" default(50)
// @Success 200 {object} PlatformRolePageResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/roles [get]
func (h *RoleHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	actor, ok := requestActor(w, r)
	if !ok || !emptyRequestBody(w, r) {
		return
	}
	query, ok := roleDirectoryQuery(w, r, true)
	if !ok {
		return
	}
	page, err := h.service.ListProjectRoles(r.Context(), actor, query)
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	response := PlatformRolePageResponse{Roles: make([]PlatformRoleSummary, 0, len(page.Roles)), NextAfterKey: page.NextAfterKey}
	for _, role := range page.Roles {
		response.Roles = append(response.Roles, PlatformRoleSummary{
			ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description, System: role.System, MFARequired: role.MFARequired, Version: role.Version,
		})
	}
	httpx.JSON(w, 200, response)
}

package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

// @Summary Revoke a custom project role as a platform operator
// @Description Fresh platform.project_access.manage and exact versions. System role assignments cannot be changed here. Removes the binding under the shared Access lock, bumps access_version only on change, preserves auth_version, and writes the immutable receipt in the same transaction. SQL permission validation observes revocation immediately; offline JWT semantics are unchanged. Blocked non-deleted targets may be stripped of custom roles. Read/reconcile the same operation after an unknown response.
// @Tags Platform Roles
// @Accept json
// @Produce json
// @Param Origin header string true "Exact platform HTTPS origin"
// @Param id path string true "Project UUID"
// @Param userId path string true "Project user UUID"
// @Param roleId path string true "Custom role UUID in this project"
// @Param body body PlatformAssignmentRequest true "Operation and expected versions; maximum 8 KiB"
// @Success 200 {object} PlatformAssignmentResponse
// @Success 202 {object} PlatformAssignmentResponse "Outcome unknown"
// @Header 200 {string} Location "Role operation URL"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 428 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/platform/projects/{id}/users/{userId}/roles/{roleId}/revoke [post]
func (h *RoleHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, domain.RoleRevoke)
}

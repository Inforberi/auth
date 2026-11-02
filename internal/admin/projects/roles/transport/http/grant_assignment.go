package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
)

// @Summary Grant a custom project role as a platform operator
// @Description Runtime-enabled platform only. Fresh platform.project_access.manage and exact project/user/role versions. System roles are forbidden. Grant checks catalog/MFA capability, caps assignments, invalidates pre-grant active sessions, and atomically records a project receipt. Same operation UUID/payload replays its original result; unknown COMMIT never means rollback. No actor/target/action override in JSON. Project MFA-required grants fail closed until capability is assembled.
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
// @Router /api/v1/platform/projects/{id}/users/{userId}/roles/{roleId}/grant [post]
func (h *RoleHandler) Grant(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, domain.RoleGrant)
}

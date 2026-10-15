package http

import "net/http"

// @Summary Assign a custom role to a user
// @Description Requires access.assignments.manage, all delegated role permissions, current role/access versions and fresh password plus MFA in one transaction. No self-grant or system-role assignment. Pending users receive access only after activation. Retry with stale versions returns conflict; a current no-op preserves the version.
// @Tags Admin Access
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Target user UUID"
// @Param roleId path string true "Role UUID"
// @Param body body AssignmentRequest true "Expected role and user assignment versions"
// @Success 200 {object} AssignmentResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/roles/{roleId} [post]
func (h *Handler) GrantRole(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, true)
}

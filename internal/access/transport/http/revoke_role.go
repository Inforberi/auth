package http

import "net/http"

// @Summary Revoke a custom role from a user
// @Description JSON body is required also for DELETE. Same permission/delegation/version/password/MFA transaction guard as grant. Self-revoke of a custom role is allowed; system role cannot be revoked. Subsequent authorization uses current SQL assignments.
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
// @Router /api/v1/admin/users/{id}/roles/{roleId} [delete]
func (h *Handler) RevokeRole(w http.ResponseWriter, r *http.Request) {
	h.changeAssignment(w, r, false)
}

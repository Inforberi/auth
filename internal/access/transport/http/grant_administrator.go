package http

import "net/http"

// @Summary Assign the system administrator role
// @Description Requires current super_admin membership, access.assignments.manage, all delegated system-role permissions and fresh password plus MFA in one transaction. No self-grant or arbitrary system role. Target must be active, have a permanent password, verified login email and enrolled TOTP, with no pending activation/temporary credentials. Requires current target auth/access and system role versions. Does not create credentials, a session, a new role or a bootstrap bypass. Authorized current-version replay is a no-op.
// @Tags Access
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Target user UUID"
// @Param body body AdministratorRequest true "Current target auth/access and super_admin role versions"
// @Success 200 {object} AssignmentResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/administrator [post]
func (h *Handler) GrantAdministrator(w http.ResponseWriter, r *http.Request) {
	h.changeAdministrator(w, r, true)
}

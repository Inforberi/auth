package http

import "net/http"

// @Summary Revoke the system administrator role
// @Description Requires current super_admin membership, access.assignments.manage, delegated system-role permissions and fresh password plus MFA. Current target auth/access and role versions are checked in the same transaction. Preserves another active administrator with permanent password, verified login email, enrolled TOTP and no pending/temporary activation. Self-revoke is allowed only with such a backup. Access changes immediately; no-op replay still requires current authority. Does not delete the account, disable MFA or change the system role itself.
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
// @Router /api/v1/admin/users/{id}/administrator [delete]
func (h *Handler) RevokeAdministrator(w http.ResponseWriter, r *http.Request) {
	h.changeAdministrator(w, r, false)
}

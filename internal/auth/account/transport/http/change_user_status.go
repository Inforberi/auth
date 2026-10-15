package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ChangeUserStatusRequest struct {
	Status              domain.Status      `json:"status" swaggertype:"string" enums:"active,blocked"`
	ExpectedAuthVersion domain.AuthVersion `json:"expectedAuthVersion" swaggertype:"integer"`
} // @name account_http.ChangeUserStatusRequest

// @Summary Block or unblock a user
// @Description Requires MFA_ENABLED, accounts.users.status.manage and fresh password plus MFA checked in the mutation transaction. Actor is derived from the current session. Requires current authVersion; changes revoke sessions and outstanding activation/recovery proofs. Unblocking does not activate pending users, restore deleted accounts or revive old sessions. Last system administrator is protected. Read/create permissions do not authorize this operation.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "User UUID"
// @Param body body ChangeUserStatusRequest true "Desired status and current authVersion"
// @Success 200 {object} UserLifecycleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/status [post]
func (h *UserLifecycleHandler) ChangeStatus(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	var input ChangeUserStatusRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	version, err := h.service.ChangeStatus(r.Context(), actor, domain.StatusChange{UserID: domain.UserID(chi.URLParam(r, "id")), ExpectedVersion: input.ExpectedAuthVersion, Status: input.Status})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, UserLifecycleResponse{AuthVersion: version})
}

package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type DeleteUserRequest struct {
	ExpectedAuthVersion domain.AuthVersion `json:"expectedAuthVersion" swaggertype:"integer"`
} // @name account_http.DeleteUserRequest

// @Summary Irreversibly delete an account
// @Description Requires MFA_ENABLED, accounts.users.delete and fresh password plus MFA in the deletion transaction. Actor comes only from the session. Current authVersion is mandatory; stale retries conflict, a retry with the current tombstone version is a no-op but still requires authorization. Uses existing atomic credential cleanup, session revocation, audit and email reservation policy. This is a retained tombstone, not complete PII erasure. No account restoration. Last system administrator is protected.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "User UUID"
// @Param body body DeleteUserRequest true "Current authVersion; deletion is irreversible"
// @Success 200 {object} UserLifecycleResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 404 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id} [delete]
func (h *UserLifecycleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	var input DeleteUserRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	version, err := h.service.Delete(r.Context(), actor, domain.AccountDeletion{UserID: domain.UserID(chi.URLParam(r, "id")), ExpectedVersion: input.ExpectedAuthVersion})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, UserLifecycleResponse{AuthVersion: version})
}

package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TemporaryProvisionRequest struct {
	IdempotencyKey string `json:"idempotencyKey" binding:"required"`
	Email          string `json:"email" binding:"required"`
} // @name password_http.TemporaryProvisionRequest

// @Summary Create a pending user with a one-time temporary password
// @Description Requires TEMPORARY_PASSWORD_ENABLED, MFA_ENABLED, accounts.users.manage and current fresh password plus MFA. Independent of invitations. Server generates the secret; response contains password only on first commit. Replay never returns it or extends TTL. No email verification, roles or session. Protect the response, do not log or cache it. Lost response requires a new reissue command after cooldown.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body TemporaryProvisionRequest true "UUID command key and unoccupied email"
// @Success 201 {object} TemporaryIssueResponse "First commit, plaintext password once"
// @Success 200 {object} TemporaryIssueResponse "Replay without password or original expiresAt"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/temporary-password [post]
func (h *TemporaryAdminHandler) Provision(w http.ResponseWriter, r *http.Request) {
	actor, ok := temporaryAdminActor(w, r)
	if !ok {
		return
	}
	var input TemporaryProvisionRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Provision(r.Context(), service.TemporaryProvisionInput{Actor: actor, IdempotencyKey: input.IdempotencyKey, Email: input.Email})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	status := http.StatusCreated
	if result.Reused {
		status = http.StatusOK
	}
	httpx.JSON(w, status, temporaryIssueResponse(result))
}

package http

import (
	"net/http"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ProvisionRequest struct {
	IdempotencyKey string `json:"idempotencyKey" binding:"required"`
	Email          string `json:"email"`
	Invite         bool   `json:"invite"`
} // @name account_http.ProvisionRequest

// @Summary Create a pending user, optionally with an email invitation
// @Description Requires INVITATIONS_ENABLED, MFA_ENABLED, accounts.users.manage and fresh password plus MFA checked in the write transaction, including replay. Actor comes only from the current session. UUID idempotency key is scoped by actor; mismatched parameters or occupied email conflict. No roles, verified email, password or session are granted. Replay does not resend mail or reactivate the account.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param body body ProvisionRequest true "UUID command key; email required when invite=true"
// @Success 201 {object} ProvisionResponse "First successful creation"
// @Success 200 {object} ProvisionResponse "Committed replay, no new invitation"
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users [post]
func (h *ProvisioningHandler) Provision(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	var input ProvisionRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Provision(r.Context(), service.ProvisionInput{Actor: actor, IdempotencyKey: input.IdempotencyKey, Email: input.Email, Invite: input.Invite})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	status := http.StatusCreated
	if result.Reused {
		status = http.StatusOK
	}
	httpx.JSON(w, status, ProvisionResponse{UserID: result.UserID, Reused: result.Reused})
}

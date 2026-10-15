package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type ReissueInvitationRequest struct {
	IdempotencyKey string `json:"idempotencyKey" binding:"required"`
} // @name account_http.ReissueInvitationRequest

// @Summary Reissue a pending user's email invitation
// @Description Requires accounts.users.manage and fresh password plus MFA; current SQL authority is checked on reads, writes and replay. UUID command key, original unverified contact, pending provisioned user only. No email changes, new user, roles, session or bypass of temporary-password activation. Cooldown and Redis budgets apply. Replay does not send another message.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Pending user UUID"
// @Param body body ReissueInvitationRequest true "New command key, or the same key for a retry"
// @Success 200 {object} ProvisionResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/invitation [post]
func (h *ProvisioningHandler) ReissueInvitation(w http.ResponseWriter, r *http.Request) {
	actor, ok := accountActor(w, r)
	if !ok {
		return
	}
	var input ReissueInvitationRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.ReissueInvitation(r.Context(), service.InvitationReissueInput{Actor: actor, UserID: domain.UserID(chi.URLParam(r, "id")), IdempotencyKey: input.IdempotencyKey})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, ProvisionResponse{UserID: result.UserID, Reused: result.Reused})
}

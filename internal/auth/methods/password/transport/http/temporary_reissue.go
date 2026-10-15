package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type TemporaryReissueRequest struct {
	IdempotencyKey string `json:"idempotencyKey" binding:"required"`
} // @name password_http.TemporaryReissueRequest

// @Summary Reissue a pending user's temporary password
// @Description Requires accounts.users.manage and current fresh password plus MFA on both preflight/replay and mutation. Only an existing pending temporary-password account, original unverified contact and cooldown; does not reset an active user's password. First commit returns a new secret once and invalidates old temporary/setup authority. Replay preserves stored expiry and never returns password. No email, roles or session are granted.
// @Tags Admin Users
// @Accept json
// @Produce json
// @Param Origin header string true "Exact allowed HTTPS origin"
// @Param id path string true "Pending temporary user UUID"
// @Param body body TemporaryReissueRequest true "UUID command key"
// @Success 200 {object} TemporaryIssueResponse
// @Failure 400 {object} httpx.ErrorResponse
// @Failure 401 {object} httpx.ErrorResponse
// @Failure 403 {object} httpx.ErrorResponse
// @Failure 409 {object} httpx.ErrorResponse
// @Failure 429 {object} httpx.ErrorResponse
// @Failure 503 {object} httpx.ErrorResponse
// @Router /api/v1/admin/users/{id}/temporary-password [post]
func (h *TemporaryAdminHandler) Reissue(w http.ResponseWriter, r *http.Request) {
	actor, ok := temporaryAdminActor(w, r)
	if !ok {
		return
	}
	var input TemporaryReissueRequest
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.Error(w, 400, "invalid_json", "invalid JSON")
		return
	}
	result, err := h.service.Reissue(r.Context(), service.TemporaryReissueInput{Actor: actor, UserID: accountdomain.UserID(chi.URLParam(r, "id")), IdempotencyKey: input.IdempotencyKey})
	if err != nil {
		h.respondError(w, r, err)
		return
	}
	httpx.JSON(w, 200, temporaryIssueResponse(result))
}
